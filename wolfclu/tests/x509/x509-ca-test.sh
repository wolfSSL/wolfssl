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


cat << EOF >> ca.conf
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE
nsComment            = "wolfSSL Generated Certificate using wolfSSL command line utility."
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ CA_default ]

dir = ./certs
database = ./index.txt
new_certs_dir = ./

certificate = \$dir/ca-cert.pem
private_key = \$dir/ca-key.pem
rand_serial = yes

default_days = 365
default_md = sha256

policy = policy_any

[ policy_any]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
EOF

cat << EOF >> ca-2.conf
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ CA_default ]

dir = ./certs
database = ./index.txt
new_certs_dir = ./
certificate = \$dir/ca-cert.pem
private_key = \$dir/ca-key.pem
RANDFILE = ./rand-file-test
serial   = ./serial-file-test
default_days = 365
default_md = sha256
unique_subject = yes

policy = policy_any

[ policy_any]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
EOF

cat << EOF >> ca-match.conf
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE

[ CA_default ]

dir = ./certs
database = ./index.txt
new_certs_dir = ./

certificate = \$dir/ca-cert.pem
private_key = \$dir/ca-key.pem
rand_serial = yes

default_days = 365
default_md = sha256

policy = policy_match

[ policy_match ]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = match
organizationalUnitName = optional
commonName             = match
emailAddress           = optional

crl_dir    = ./crls-test
crlnumber  = ./crlnumber-test
crl        = ./certs/crl.pem
EOF

touch index.txt
cat << EOF >> ca-crl.conf
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE

[ CA_default ]

dir = ./certs
database = ./index.txt
new_certs_dir = ./

certificate = \$dir/ca-cert.pem
private_key = \$dir/ca-key.pem
rand_serial = yes

default_days = 365
default_md = sha256

policy = policy_any

[ policy_any]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

crl_dir    = ./crls-test
crlnumber  = ./crlnumber-test
crl        = ./certs/crl.pem
EOF

touch index.txt
run_success "ca -h"
run_success "ca -help"
run_success "req -key ./certs/server-key.pem -subj O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit -out tmp-ca.csr"

# testing reading bad conf file
run_fail "ca -config ca-example.conf -in tmp-ca.csr -out tmp.pem -md sha256 -selfsign -keyfile ./certs/ca-key.pem"

# testing out selfsign
run_fail "ca -config ca.conf -in tmp-ca.csr -out tmp.pem -md sha256 -selfsign -keyfile ./certs/ca-key.pem"
run_success "ca -config ca.conf -in tmp-ca.csr -out test_ca.pem -md sha256 -selfsign -keyfile ./certs/server-key.pem"
SUBJ=`./wolfssl x509 -in test_ca.pem -subject -noout`
ISSU=`./wolfssl x509 -in test_ca.pem -issuer -noout`
if [ "$SUBJ" != "$ISSU" ]; then
    echo "subject and issuer missmatch on self signed cert"
    exit 99
fi
run_fail "verify -CAfile ./certs/server-cert.pem test_ca.pem"
run_fail "verify -CAfile ./certs/ca-cert.pem test_ca.pem"

# create a certificate and then verify it
run_success "ca -config ca.conf -in tmp-ca.csr -out test_ca.pem"
run_success "verify -CAfile ./certs/ca-cert.pem test_ca.pem"

# override almost all info from config file
run_success "ca -config ca.conf -in tmp-ca.csr -out test_ca.pem -extensions usr_cert -md sha512 -days 3650 -cert ./certs/ca-ecc-cert.pem -keyfile ./certs/ca-ecc-key.pem"
rm -f test_ca.pem

# test key missmatch
run_fail "ca -config ca.conf -in tmp-ca.csr -out test_ca.pem -keyfile ./certs/ecc-key.pem"

# hit unique subject fail case
rm -f serial-file-test
echo "01" > serial-file-test
touch rand-file-test
run_fail "ca -config ca-2.conf -in tmp-ca.csr -out test_ca.pem"
rm index.txt
touch index.txt
run_success "ca -config ca-2.conf -in tmp-ca.csr -out test_ca.pem"
run_success "x509 -in test_ca.pem -noout -serial"
if [ "$RESULT" != "serial=01" ]; then
    echo "Unexpected serial number!"
    exit 99
fi

# test rand file
wc -c rand-file-test | grep 256
if [ $? != 0 ]; then
    echo "rand file was not 256 bytes"
    exit 99
fi
RAND=`cat rand-file-test`

# test increment of serial number
rm index.txt
touch index.txt
run_success "ca -config ca-2.conf -in tmp-ca.csr -out test_ca.pem"
run_success "x509 -in test_ca.pem -noout -serial"
if [ "$RESULT" != "serial=02" ]; then
    echo "Unexpected serial number!"
    exit 99
fi

# test rand file
NEW_RAND=`cat rand-file-test`
if [ "$RAND" == "$NEW_RAND" ]; then
    echo "rand file was the same.."
    echo $NEW_RAND | base64
    echo $RAND | base64
    exit 99
fi

# testing on policy section in conf file
echo "Testing policy section"

# no common name when is 'supplied'
run_success "req -key ./certs/server-key.pem -subj O=wolfSSL/C=US/ST=MT/L=Bozeman/OU=org-unit -out tmp-ca.csr"
echo "Test fail when common name not supplied"
run_fail "ca -config ca.conf -in tmp-ca.csr -out tmp.pem -md sha256 -keyfile ./certs/ca-key.pem"
echo "Test fail when common name not supplied 'ca-match.conf'"
run_fail "ca -config ca-match.conf -in tmp-ca.csr -out tmp.pem -md sha256 -keyfile ./certs/ca-key.pem"
echo "Test success when common name supplied"
run_success "req -key ./certs/server-key.pem -subj O=Sawtooth/CN=www.wolfclu.com/C=US/ST=MT/L=Bozeman/OU=org-unit -out tmp-ca.csr"
run_success "ca -config ca.conf -in tmp-ca.csr -out tmp.pem -md sha256 -keyfile ./certs/ca-key.pem"

# common name mismatch
run_success "req -key ./certs/server-key.pem -subj O=Sawtooth/CN=www.wolfclu.com/C=US/ST=MT/L=Bozeman/OU=org-unit -out tmp-ca.csr"
run_fail "ca -config ca-match.conf -in tmp-ca.csr -out tmp.pem -md sha256 -keyfile ./certs/ca-key.pem"

rm -f tmp.pm
rm -f rand-file-test
rm -f serial-file-test
rm -f tmp-ca.csr
rm -f ca.conf
rm -f ca-2.conf
rm -f ca-crl.conf
rm -f ca-match.conf
rm -f index.txt

echo "Done"
exit 0



