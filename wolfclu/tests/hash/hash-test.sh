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

run_success() {
    RESULT=`./wolfssl $1`
    if [ $? != 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1`
    if [ $? == 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_success "-hash sha -in certs/ca-cert.pem -base64enc"
EXPECTED="46060ebc47f6f5486addd5658a7a2eb5ef7a9913"
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi

run_success "-hash sha256 -in certs/ca-cert.pem"
EXPECTED="c68d5b8d17f551e3a9881968c2fe281bf8af9e6a16a1ecc97740a76d23858053"
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi

run_success "-hash sha384 -in certs/ca-cert.pem"
EXPECTED="55c6dabf204a2795a71b4b62594ed89348333821a87b160a08a5ed47ddc52373038792d605aa365762e4028d51c11972"
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi

run_success "-hash sha512 -in certs/ca-cert.pem"
EXPECTED="4eb961036db9c181d9e48f5bc0ff631e4753eac74209d6a199f99305fb614483a1e1a55922d54c17fac1b472eac6a7ffe2eb9be48dd87670be6264d25aa4493a"
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi


run_success "md5 certs/ca-cert.pem"
EXPECTED="21ea0398596253752e6cd2195e7abf3c"
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi

run_success "sha256 certs/ca-cert.pem"
EXPECTED="c68d5b8d17f551e3a9881968c2fe281bf8af9e6a16a1ecc97740a76d23858053"
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi

run_success "sha384 certs/ca-cert.pem"
EXPECTED="55c6dabf204a2795a71b4b62594ed89348333821a87b160a08a5ed47ddc52373038792d605aa365762e4028d51c11972"
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi

run_success "sha512 certs/ca-cert.pem"
EXPECTED="4eb961036db9c181d9e48f5bc0ff631e4753eac74209d6a199f99305fb614483a1e1a55922d54c17fac1b472eac6a7ffe2eb9be48dd87670be6264d25aa4493a"
if [ "$RESULT" != "$EXPECTED" ]
then
    echo "found unexpected output"
    exit 99
fi


echo "Done"
exit 0
