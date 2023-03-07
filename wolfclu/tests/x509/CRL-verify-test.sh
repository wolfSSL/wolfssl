#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

run_success() {
    RESULT=`./wolfssl $1`
    if [ $? != 0 ]; then
        echo "Fail on ./wolfssl $1"
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1`
    if [ $? == 0 ]; then
        echo "Fail on ./wolfssl $1"
        exit 99
    fi
}


# Test if CRL compiled in
RESULT=`./wolfssl crl -CAfile ./certs/ca-cert.pem -in ./certs/crl.pem 2>&1`
echo $RESULT | grep "recompile wolfSSL with CRL support"
if [ $? == 0 ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi


# check that the CRL was printed out
run_success "crl -CAfile ./certs/ca-cert.pem -in ./certs/crl.pem"
echo $RESULT | grep BEGIN
if [ $? != 0 ]; then
    echo "CRL not printed when should have been"
    exit 99
fi


# check that the CRL was not printed out
run_success "crl -noout -CAfile ./certs/ca-cert.pem -in ./certs/crl.pem"
echo $RESULT | grep "BEGIN X509 CRL"
if [ $? == 0 ]; then
    echo "CRL printed when should not have been"
    exit 99
fi

# check that 1 is returned on fail to parse CRL
run_fail "crl -inform DER -outform PEM -in ./certs/ca-cert.der"

run_success "req -new -days 3650 -key ./certs/server-key.pem -subj /O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit -out client.pem -x509"
run_fail "crl -noout -CAfile client.pem -in ./certs/crl.pem"
rm -rf client.pem

# fail to load
run_fail "crl -noout -CAfile ./certs/ca-cer.pem -in ./certs/crl.pem"
run_fail "crl -noout -CAfile ./certs/ca-cert.pem -in ./certs/cl.pem"

# fail to verify
run_fail "crl -noout -CAfile ./certs/client-cert.pem -in ./certs/crl.pem"

run_success "crl -inform DER -outform PEM -in ./certs/crl.der -out ./test-crl.pem"
run_success "crl -noout -CAfile ./certs/ca-cert.pem -in ./test-crl.pem"
run_fail "crl -inform DER -outform PEM -in ./certs/ca-cert.der -out test.crl.pem"
rm -f test-crl.pem

rm -f test.crl.pem
run_fail "crl -inform DER -outform PEM -in ./certs/ca-cert.der -out test.crl.pem"
if [ -f "test.crl.pem" ]; then
    echo "file test.crl.pem should not have been created on fail case"
    exit 99
fi

RESULT=`./wolfssl crl -in certs/crl.pem -text`
echo $RESULT | grep "CRL print not available in version of wolfSSL"
if [ $? == 0 ]; then
    # check the CRL -text arg
    run_success "crl -noout -in ./certs/crl.pem -text"
    echo $RESULT | grep "Certificate Revocation List (CRL):"
    if [ $? != 0 ]; then
        echo $RESULT
        echo "Couldn't find expected output"
        exit 99
    fi
fi

echo "Done"
exit 0

