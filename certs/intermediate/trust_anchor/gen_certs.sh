#!/bin/bash

# Regenerate the certificate set used by the chain tests of
# X509_verify_cert() in tests/api/test_ossl_x509_str.c.
#
#   self-cert        a self-signed CA
#   self-copy-cert   the same name and key as self-cert, another serial
#   root-cert        a self-signed CA
#   link-cert        the name of root-cert with its own key, issued by
#                    root-cert: self-issued, but not self-signed
#   link-noaki-cert  link-cert without an authority key identifier
#   leaf-cert        issued by link-cert
#   notca-twin-cert  a CA with the name of notca-root-cert
#                    (gen_dated_certs.sh) and the key of leaf-cert, issued by
#                    root-cert, without a subject key id
#   ec-name-root-cert an EC P-256 root with the name of root-cert, without
#                    key ids
#
# RSA-2048 / SHA-256, ~30 year validity so the regression does not expire.
#
# Requires: openssl.

set -e
cd "$(dirname "$0")"

OPENSSL="${OPENSSL:-openssl}"
DAYS=10957
RSA_BITS=2048

CA_EXT=$(mktemp)
CA_NOAKI_EXT=$(mktemp)
CA_NOSKID_EXT=$(mktemp)
LEAF_EXT=$(mktemp)
trap 'rm -f "$CA_EXT" "$CA_NOAKI_EXT" "$CA_NOSKID_EXT" "$LEAF_EXT" *.csr' \
    EXIT

cat > "$CA_EXT" <<'EXT'
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EXT

cat > "$CA_NOAKI_EXT" <<'EXT'
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = none
EXT

cat > "$CA_NOSKID_EXT" <<'EXT'
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = none
authorityKeyIdentifier = keyid:always
EXT

cat > "$LEAF_EXT" <<'EXT'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EXT

genkey() { "$OPENSSL" genrsa -out "$1" "$RSA_BITS" 2>/dev/null; }

# Self-sign: selfsign <key> <cert> <CN> <serial>
selfsign() {
    "$OPENSSL" req -x509 -new -key "$1" -sha256 -subj "/CN=$3" -set_serial "$4" \
        -days "$DAYS" -extensions v3 \
        -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n%s' \
            "$(cat "$CA_EXT")") \
        -out "$2"
}

# Sign a CSR: signcert <csr> <cert> <issuer-cert> <issuer-key> <serial> <ext>
signcert() {
    "$OPENSSL" x509 -req -in "$1" -CA "$3" -CAkey "$4" -set_serial "$5" \
        -sha256 -days "$DAYS" -extfile "$6" -out "$2" 2>/dev/null
}

# Self-signed copies -----------------------------------------------------------
genkey self-key.pem
selfsign self-key.pem self-cert.pem "wolfSSL Trust-Anchor Test Self-Signed" 1
selfsign self-key.pem self-copy-cert.pem \
    "wolfSSL Trust-Anchor Test Self-Signed" 2

# Self-issued link cert --------------------------------------------------------
genkey root-key.pem
selfsign root-key.pem root-cert.pem "wolfSSL Trust-Anchor Test Root" 1

genkey link-key.pem
"$OPENSSL" req -new -key link-key.pem -sha256 \
    -subj "/CN=wolfSSL Trust-Anchor Test Root" -out link.csr
signcert link.csr link-cert.pem root-cert.pem root-key.pem 2 "$CA_EXT"
signcert link.csr link-noaki-cert.pem root-cert.pem root-key.pem 3 \
    "$CA_NOAKI_EXT"

genkey leaf-key.pem
"$OPENSSL" req -new -key leaf-key.pem -sha256 \
    -subj "/CN=wolfSSL Trust-Anchor Test Leaf" -out leaf.csr
signcert leaf.csr leaf-cert.pem link-cert.pem link-key.pem 4 "$LEAF_EXT"

# Another signer's name --------------------------------------------------------
"$OPENSSL" req -new -key leaf-key.pem -sha256 \
    -subj "/CN=wolfSSL Chain Test Not CA Root" -out twin.csr
signcert twin.csr notca-twin-cert.pem root-cert.pem root-key.pem 5 \
    "$CA_NOSKID_EXT"

# A root of another key type --------------------------------------------------
"$OPENSSL" ecparam -name prime256v1 -genkey -noout -out ec-name-root-key.pem
"$OPENSSL" req -x509 -new -key ec-name-root-key.pem -sha256 \
    -subj "/CN=wolfSSL Trust-Anchor Test Root" -set_serial 6 -days "$DAYS" \
    -extensions v3 \
    -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n%s\n%s\n%s\n' \
        "basicConstraints = critical, CA:TRUE" \
        "keyUsage = critical, keyCertSign, cRLSign" \
        "subjectKeyIdentifier = none") \
    -out ec-name-root-cert.pem
rm -f ec-name-root-key.pem

echo "Completed"
