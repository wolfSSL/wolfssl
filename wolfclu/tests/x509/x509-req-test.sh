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
    if [ -z "$2" ]; then
        RESULT=`./wolfssl $1`
    else
        RESULT=`echo "$2" | ./wolfssl $1`
    fi
    if [ $? != 0 ]; then
        echo "Fail on ./wolfssl $1"
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
        echo "Fail on ./wolfssl $1"
        exit 99
    fi
}


cat << EOF >> test.conf
[ req ]
distinguished_name =req_distinguished_name
attributes =req_attributes
prompt =no
x509_extensions = v3_req
req_extensions = v3_req
[ req_distinguished_name ]
countryName =US
stateOrProvinceName =Montana
localityName =Bozeman
organizationName =wolfSSL
commonName = testing
[ req_attributes ]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[ v3_alt_ca ]
basicConstraints = CA:TRUE
keyUsage = digitalSignature
subjectAltName = @alt_names
[ v3_alt_req_full ]
basicConstraints = CA:TRUE
keyUsage = digitalSignature
subjectAltName = @alt_names_full_skip
[alt_names]
DNS.1 = extraName
DNS.2 = alt-name
DNS.3 = thirdName
IP.1 = 2607:f8b0:400a:80b::2004
DNS.4 = 2607:f8b0:400a:80b::2004 (google.com)
IP.2 = 127.0.0.1
[alt_names_full_skip]
DNS.1 = extraName
DNS.2 = alt-name
DNS.4 = thirdName
IP.1 = 2607:f8b0:400a:80b::2004
DNS.5 = 2607:f8b0:400a:80b::2004 (google.com)
IP.2 = 127.0.0.1
DNS.6 = thirdName
DNS.7 = thirdName
DNS.8 = thirdName
DNS.9 = thirdName
DNS.10 = tenthName
EOF

cat << EOF >> test-prompt.conf
[ req ]
distinguished_name =req_distinguished_name
attributes =req_attributes
x509_extensions = v3_req
req_extensions = v3_req
[ req_distinguished_name ]
countryName = 2 Letter Country Name
countryName_default = US
countryName_max = 2
coutnryName_min = 2
[ req_attributes ]
[ v3_req ]
basicConstraints = critical,CA:true
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
EOF


run_success "req -new -days 3650 -key ./certs/server-key.pem -subj O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit -out tmp.cert -x509"

SUBJECT=`./wolfssl x509 -in tmp.cert -text | grep Subject:`
EXPECTED="        Subject: O=wolfSSL, C=US, ST=WA, L=Seattle, CN=wolfSSL, OU=org-unit"
if [ "$SUBJECT" != "$EXPECTED" ]
then
    echo "found unexpected result"
    echo "Got      : $SUBJECT"
    echo "Expected : $EXPECTED"
    exit 99
fi
rm -f tmp.cert

# no parameter -conf
#run_fail "req -new -key ./certs/server-key.pem -conf ./test.conf -out tmp.csr"

run_success "req -new -key ./certs/server-key.pem -config ./test.conf -out tmp.csr"
run_success "req -text -in tmp.csr"

# fail when extensions can not be found
run_fail "req -new -extensions v3_alt_ca_not_found -key ./certs/server-key.pem -config ./test.conf -x509 -out alt.crt"
run_success "req -new -extensions v3_alt_ca -key ./certs/server-key.pem -config ./test.conf -x509 -out alt.crt"
run_success "x509 -in alt.crt -text -noout"
echo "$RESULT" | grep "CA:TRUE"
if [ $? != 0 ]; then
    echo "was expecting alt extensions to have CA set"
    exit 99
fi

# test pem to der and back again
run_success "req -inform pem -outform der -in tmp.csr -out tmp.csr.der"
run_success "req -inform der -outform pem -in tmp.csr.der -out tmp.csr.pem"
diff tmp.csr.pem tmp.csr
if [ $? != 0 ]; then
    echo "transforming from der and back to pem mismatch"
    echo "tmp.csr != tmp.csr.pem"
    exit 99
fi
rm -f tmp.csr.pem
rm -f tmp.csr.der
rm -f tmp.csr

run_success "req -new -key ./certs/server-key.pem -config ./test.conf -x509 -out tmp.cert"
SUBJECT=`./wolfssl x509 -in tmp.cert -text | grep Subject:`
EXPECTED="        Subject: C=US, ST=Montana, L=Bozeman, O=wolfSSL, CN=testing"
if [ "$SUBJECT" != "$EXPECTED" ]
then
    echo "found unexpected result"
    echo "Got      : $SUBJECT"
    echo "Expected : $EXPECTED"
    exit 99
fi
rm -f tmp.cert

# test default basic constraints extenstion
run_success "req -new -x509 -key certs/server-key.pem -subj O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit -out tmp.cert"
run_success "x509 -in tmp.cert -text -noout"
echo "$RESULT" | grep "CA:TRUE"
if [ $? != 0 ]; then
    echo "was expecting cert extensions to have CA set to TRUE"
    exit 99
fi
rm -f tmp.cert

run_success "req -new -newkey rsa:2048 -config ./test.conf -x509 -out tmp.cert -passout stdin" "long test password"
echo $RESULT | grep "ENCRYPTED"
if [ $? -ne 0 ]; then
    echo "no encrypted key found in result"
    exit 99
fi
rm -f tmp.cert

#testing hash and key algos
run_success "req -new -days 3650 -rsa -key ./certs/server-key.pem -config ./test.conf -out tmp.cert -x509"
rm -f tmp.cert
run_success "req -new -days 3650 -ed25519 -key ./certs/server-key.pem -config ./test.conf -out tmp.cert -x509"
rm -f tmp.cert
run_success "req -new -days 3650 -sha -key ./certs/server-key.pem -config ./test.conf -out tmp.cert -x509"
rm -f tmp.cert
run_success "req -new -days 3650 -sha224 -key ./certs/server-key.pem -config ./test.conf -out tmp.cert -x509"
rm -f tmp.cert
run_success "req -new -days 3650 -sha256 -key ./certs/server-key.pem -config ./test.conf -out tmp.cert -x509"
rm -f tmp.cert
run_success "req -new -days 3650 -sha384 -key ./certs/server-key.pem -config ./test.conf -out tmp.cert -x509"
rm -f tmp.cert
run_success "req -new -days 3650 -sha512 -key ./certs/server-key.pem -config ./test.conf -out tmp.cert -x509"
rm -f tmp.cert

run_success "req -new -newkey rsa:2048 -keyout new-key.pem -config ./test.conf -x509 -out tmp.cert -passout stdin" "long test password"

run_success "req -new -key ./certs/ca-key.pem -config ./test.conf -extensions v3_alt_req_full -out tmp.cert"
run_success "req -in ./tmp.cert -noout -text"
echo $RESULT | grep tenthName
if [ $? -ne 0 ]; then
    echo Failed to find tenthName in alt names
    exit 99
fi

#test passout
run_success "req -newkey rsa:2048 -keyout new-key.pem -config ./test.conf -out tmp.cert -passout pass:123456789wolfssl -outform pem -sha256"
run_success "rsa -in new-key.pem -passin pass:123456789wolfssl"

rm -f tmp.cert

run_success "req -new -x509 -key ./certs/ca-key.pem -config ./test-prompt.conf -out tmp.cert" "AA"
run_fail "req -new -x509 -key ./certs/ca-key.pem -config ./test-prompt.conf -out tmp.cert" "LONG"

rm -f new-key.pem
rm -f test.conf
rm -f test-prompt.conf

# test printing out CSR attributes, older versions of wolfSSL will fail this
RESULT=`./wolfssl req -text -noout -in ./certs/attributes-csr.pem`
if [ $? -eq 0 ]; then
    echo $RESULT | grep "initials" | grep "abc"
    if [ $? -ne 0 ]; then
        echo "no initials attribute found"
        exit 99
    fi
    echo $RESULT | grep "dnQualifier" | grep "dn"
    if [ $? -ne 0 ]; then
        echo "no dnQualifier attribute found"
        exit 99
    fi
    echo $RESULT | grep "challengePassword" | grep "test"
    if [ $? -ne 0 ]; then
        echo "no challengePassword attribute found"
        exit 99
    fi
    echo $RESULT | grep "givenName" | grep "Given Name"
    if [ $? -ne 0 ]; then
        echo "no givenName attribute found"
        exit 99
    fi
    echo $RESULT | grep "surname"
    if [ $? -ne 0 ]; then
        echo "no surname attribute found"
        exit 99
    fi
fi

echo "Done"
exit 0


