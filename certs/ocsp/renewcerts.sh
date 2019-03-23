#!/bin/sh

check_result(){
    if [ $1 -ne 0 ]; then
        if [ -n "$2" ]; then
            echo "Step Failed, Abort"
        else
            echo "$2 Failed, Abort"
        fi
        exit 1
    else
        echo "Step Succeeded"
    fi
}

echo "OCSP renew certs Step 1"
openssl req                \
    -new                   \
    -key  root-ca-key.pem  \
    -out  root-ca-cert.csr \
    -config ../renewcerts/wolfssl.cnf \
    -subj "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Engineering/CN=wolfSSL root CA/emailAddress=info@wolfssl.com"
check_result $? ""

echo "OCSP renew certs Step 2"
openssl x509                  \
    -req -in root-ca-cert.csr \
    -extfile openssl.cnf      \
    -extensions v3_ca         \
    -days 1000                \
    -signkey root-ca-key.pem  \
    -set_serial 99            \
    -out root-ca-cert.pem
check_result $? ""

rm root-ca-cert.csr
echo "OCSP renew certs Step 3"
openssl x509 -in root-ca-cert.pem -text > tmp.pem
check_result $? ""
mv tmp.pem root-ca-cert.pem

# $1 cert, $2 name, $3 ca, $4 extensions, $5 serial
update_cert() {
    echo "Updating certificate \"$1-cert.pem\""
    openssl req             \
        -new                \
        -key  "$1"-key.pem  \
        -out  "$1"-cert.csr \
        -config ../renewcerts/wolfssl.cnf \
        -subj "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Engineering/CN=$2/emailAddress=info@wolfssl.com"
    check_result $? "Step 1"

    openssl x509               \
        -req -in "$1"-cert.csr \
        -extfile openssl.cnf   \
        -extensions "$4"       \
        -days 1000             \
        -CA "$3"-cert.pem      \
        -CAkey "$3"-key.pem    \
        -set_serial "$5"       \
        -out "$1"-cert.pem
    check_result $? "Step 2"

    rm "$1"-cert.csr
    openssl x509 -in "$1"-cert.pem -text > "$1"_tmp.pem
    check_result $? "Step 3"
    mv "$1"_tmp.pem "$1"-cert.pem
    cat "$3"-cert.pem >> "$1"-cert.pem
}

update_cert intermediate1-ca "wolfSSL intermediate CA 1"       root-ca          v3_ca   01
update_cert intermediate2-ca "wolfSSL intermediate CA 2"       root-ca          v3_ca   02
update_cert intermediate3-ca "wolfSSL REVOKED intermediate CA" root-ca          v3_ca   03 # REVOKED

update_cert ocsp-responder   "wolfSSL OCSP Responder"          root-ca          v3_ocsp 04

update_cert server1          "www1.wolfssl.com"                intermediate1-ca v3_req1 05
update_cert server2          "www2.wolfssl.com"                intermediate1-ca v3_req1 06 # REVOKED
update_cert server3          "www3.wolfssl.com"                intermediate2-ca v3_req2 07
update_cert server4          "www4.wolfssl.com"                intermediate2-ca v3_req2 08 # REVOKED
update_cert server5          "www5.wolfssl.com"                intermediate3-ca v3_req3 09
