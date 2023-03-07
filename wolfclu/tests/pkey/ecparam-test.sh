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

run "ecparam -genkey -name secp384r1 -out ecparam.key"
run "ecparam -text -in ecparam.key"
EXPECTED="Curve Name : SECP384R1
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----"
if [ "$RESULT" != "$EXPECTED" ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi
rm -f ecparam.key

run "ecparam -text -in ./certs/ecc-key.pem"
EXPECTED="Curve Name : SECP256R1
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----"
if [ "$RESULT" != "$EXPECTED" ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

# pem -> der
run "ecparam -in certs/ecc-key.pem -out ecc-key.der -outform der"

# not yet supported reading only parameters with no key
run_fail "ecparam -in ecc-key.der -inform der -out ecc-key.pem -outform pem"
rm -f ecc-key.der

run "ecparam -genkey -out ecc-key.der -outform der"

run_fail "ecparam -in certs/ca-key.pem -text"


# get all possible curve name types and test @TODO leaving out SAKKE for now
NAMES=`./wolfssl ecparam -help | grep -A 100 "name options" | tr -d '[:blank:]' | grep -v "options" | grep -v "SAKKE"`

for name in $NAMES; do
    CURRENT="${name//[$'\t\r\n']}"
    run "ecparam -genkey -name $CURRENT -out tmp_ecparam.key"
    run "ecparam -text -in tmp_ecparam.key -out tmp_ecparam_text"
    printf "grep $CURRENT tmp_ecparam_text\n"
    grep $CURRENT tmp_ecparam_text
    if [ "$?" != "0" ]; then
        echo Failed when testing curve name $CURRENT
        exit 99
    fi
    rm -rf tmp_ecparam.key
    rm -rf tmp_ecparam_text
done

# test an unknown curve name
run_fail "ecparam -genkey -name bad_curve_name -out tmp_ecparam.key"
if [ -f tmp_ecparam.key ]; then
    echo File tmp_ecparam.key should not have been created
    exit 99
fi

# re-run the test but now with genkey command
for name in $NAMES; do
    CURRENT="${name//[$'\t\r\n']}"
    run "genkey ecc -name $CURRENT -outform PEM -out tmp_ecparam"
    run "ecparam -text -in tmp_ecparam.priv -out tmp_ecparam_text"
    printf "grep $CURRENT tmp_ecparam_text\n"
    grep $CURRENT tmp_ecparam_text
    if [ "$?" != "0" ]; then
        echo Failed when testing curve name $CURRENT
        exit 99
    fi
    rm -rf tmp_ecparam.priv
    rm -rf tmp_ecparam.pub
    rm -rf tmp_ecparam_text
done

echo "Done"
exit 0

