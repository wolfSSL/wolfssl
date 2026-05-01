#!/bin/sh

# Create a minimal openssl config for `openssl req`. All DN fields come from
# -subj, but openssl req still requires a [distinguished_name] section to
# exist in the config. Using this temp file avoids relying on the system
# openssl.cnf (which may not exist when testing with a custom OpenSSL build).
WOLF_REQ_CONF=$(mktemp)
printf '[req]\ndistinguished_name=req_dn\n[req_dn]\n' > "$WOLF_REQ_CONF"
trap 'rm -f "$WOLF_REQ_CONF"' EXIT

# $1 cert, $2 name, $3 ca, $4 extensions, $5 serial
update_cert(){

    openssl req           \
        -new              \
        -config "$WOLF_REQ_CONF" \
        -key  $1-key.pem  \
        -out  $1-cert.csr \
        -subj "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Engineering/CN=$2/emailAddress=info@wolfssl.com"

    openssl x509             \
        -req -in $1-cert.csr \
        -extfile $6          \
        -extensions $4       \
        -days 1000           \
        -CA $3-cert.pem      \
        -CAkey $3-key.pem    \
        -set_serial $5       \
        -out $1-cert.pem     \
        -sha256

    rm $1-cert.csr
    openssl x509 -in $1-cert.pem -text > $1_tmp.pem
    mv $1_tmp.pem $1-cert.pem
    cat $3-cert.pem >> $1-cert.pem
}



printf '%s\n' "Using CNF: $1"

openssl req                \
    -new                   \
    -config "$WOLF_REQ_CONF" \
    -key  root-ca-key.pem  \
    -out  root-ca-cert.csr \
    -subj "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Engineering/CN=wolfSSL root CA/emailAddress=info@wolfssl.com"

openssl x509                  \
    -req -in root-ca-cert.csr \
    -extfile $1      \
    -extensions v3_ca         \
    -days 1000                \
    -signkey root-ca-key.pem  \
    -set_serial 99            \
    -out root-ca-cert.pem     \
    -sha256

rm root-ca-cert.csr
openssl x509 -in root-ca-cert.pem -text > tmp.pem
mv tmp.pem root-ca-cert.pem

# imposter-root-ca: self-signed cert sharing the legitimate root-ca DN but
# with a different key. Used to test that OCSP responder authorization is
# bound to the CertID issuerKeyHash, not just the issuer name.
openssl req                            \
    -new                               \
    -config "$WOLF_REQ_CONF"           \
    -key  imposter-root-ca-key.pem     \
    -out  imposter-root-ca-cert.csr    \
    -subj "/C=US/ST=Washington/L=Seattle/O=wolfSSL/OU=Engineering/CN=wolfSSL root CA/emailAddress=info@wolfssl.com"

openssl x509                                \
    -req -in imposter-root-ca-cert.csr      \
    -extfile $1                             \
    -extensions v3_ca                       \
    -days 1000                              \
    -signkey imposter-root-ca-key.pem       \
    -set_serial 199                         \
    -out imposter-root-ca-cert.pem          \
    -sha256

rm imposter-root-ca-cert.csr
openssl x509 -in imposter-root-ca-cert.pem -text > imposter-root-ca-cert_tmp.pem
mv imposter-root-ca-cert_tmp.pem imposter-root-ca-cert.pem

update_cert intermediate1-ca "wolfSSL intermediate CA 1"       root-ca          v3_ca   01 $1
update_cert intermediate2-ca "wolfSSL intermediate CA 2"       root-ca          v3_ca   02 $1
update_cert intermediate3-ca "wolfSSL REVOKED intermediate CA" root-ca          v3_ca   03 $1 # REVOKED

update_cert ocsp-responder   "wolfSSL OCSP Responder"          root-ca          v3_ocsp 04 $1

update_cert server1          "www1.wolfssl.com"                intermediate1-ca v3_req1 05 $1
update_cert server2          "www2.wolfssl.com"                intermediate1-ca v3_req1 06 $1 # REVOKED
update_cert server3          "www3.wolfssl.com"                intermediate2-ca v3_req2 07 $1
update_cert server4          "www4.wolfssl.com"                intermediate2-ca v3_req2 08 $1 # REVOKED
update_cert server5          "www5.wolfssl.com"                intermediate3-ca v3_req3 09 $1
