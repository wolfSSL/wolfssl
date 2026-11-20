#!/usr/bin/env bash
# Generates the IEEE 802.1AR IDevID test PKI. Needs OpenSSL 3.4 or later.
set -euo pipefail

cd "$(dirname "$0")"
CNF=idevid.cnf
FOREVER=99991231235959Z
CA_START=20260101000000Z
PROD_DATE=20261001120000Z

ecc_key() {
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"
}
rsa_key() {
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1"
}

# sign <name> <subject> <key> <ca-name> <ext-section> <serial> [notBefore]
sign() {
    openssl req -new -key "$3" -subj "$2" -config "$CNF" -out "$1.csr"
    openssl x509 -req -in "$1.csr" -CA "$4-cert.pem" -CAkey "$4-key.pem" \
        -set_serial "$6" -not_before "${7:-$PROD_DATE}" -not_after "$FOREVER" \
        -extfile "$CNF" -extensions "$5" -sha256 -out "$1-cert.pem"
    openssl x509 -in "$1-cert.pem" -outform DER -out "$1-cert.der"
    rm -f "$1.csr"
}

ecc_key root-key.pem
openssl req -x509 -new -key root-key.pem -config "$CNF" -extensions root_ext \
    -subj "/C=US/O=Example Manufacturer/CN=Example IDevID Root CA" \
    -set_serial 1 -not_before "$CA_START" -not_after "$FOREVER" -sha256 \
    -out root-cert.pem
openssl x509 -in root-cert.pem -outform DER -out root-cert.der

ecc_key int-key.pem
sign int "/C=US/O=Example Manufacturer/CN=Example IDevID Issuing CA" \
    int-key.pem root int_ext 2 "$CA_START"

ecc_key int-nc-key.pem
sign int-nc "/C=US/O=Example Manufacturer/CN=Example IDevID Constrained CA" \
    int-nc-key.pem root int_nc_ext 3 "$CA_START"

ecc_key dev-key.pem
rsa_key dev-rsa-key.pem

DEV_DN="/C=US/O=Example Manufacturer/serialNumber=SN-0001/CN=Example Device"
NOCN_DN="/C=US/O=Example Manufacturer/serialNumber=SN-0001"

sign dev-ecc          "$DEV_DN"  dev-key.pem     int dev_ext           100
sign dev-ecc-nocn     "$NOCN_DN" dev-key.pem     int dev_ext           101
sign dev-ecc-dns      "$DEV_DN"  dev-key.pem     int dev_dns_ext       103
sign dev-ecc-masacrit "$DEV_DN"  dev-key.pem     int dev_masa_crit_ext 104
sign dev-ecc-eku      "$DEV_DN"  dev-key.pem     int dev_eku_ext       105
sign dev-rsa          "$DEV_DN"  dev-rsa-key.pem int dev_ext           107
sign dev-ecc-nc       "$NOCN_DN" dev-key.pem     int-nc dev_ext        108
sign dev-ecc-nc-dns   "$NOCN_DN" dev-key.pem     int-nc dev_dns_ext    109

cat dev-ecc-cert.pem int-cert.pem > dev-ecc-chain.pem
cat dev-rsa-cert.pem int-cert.pem > dev-rsa-chain.pem
rm -f root-key.pem root-cert.der int-nc-key.pem int-nc-cert.der dev-*-cert.pem
