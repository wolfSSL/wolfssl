#!/usr/bin/env bash
#
# gen-akid-serial.sh
# Certs for the AKID authorityCertIssuer and authorityCertSerialNumber
# checks (RFC 5280, 4.2.1.1). Keys are kept so the certs can be re-signed.
#
# root-cert.pem         Root CA.
# ca-cert.pem           CA under the root, serial 008A11 (sign byte).
# ca-twin-cert.pem      Same name and key as ca-cert.pem, serial 2BAD.
# ca-otherkey-cert.pem  Same name as ca-cert.pem, another key, serial 3C3C.
# leaf-cert.pem         Issued by the CA. AKID names ca-cert.pem.
# leaf-twin-cert.pem    Issued by the CA key. AKID names ca-twin-cert.pem.
# leaf-issuer-cert.pem  Issued by the CA key. AKID has the serial of
#                       ca-cert.pem but another issuer name.
# leaf-otherkey-cert.pem Issued by the CA key. AKID has the key id of
#                       ca-cert.pem and the serial of ca-otherkey-cert.pem.

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$DIR"

DAYS=10950
CA_SUBJ="/C=US/O=wolfSSL/OU=AKID Serial/CN=AKID Serial CA"

cat > "$WORK/ext.cnf" <<'EOT'
[req]
distinguished_name = dn
[dn]
[root]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer:always
[leaf]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer:always
EOT

for k in root ca leaf; do
    if [ ! -f "$k-key.pem" ]; then
        openssl ecparam -name prime256v1 -genkey -noout | \
            openssl pkcs8 -topk8 -nocrypt -out "$k-key.pem"
    fi
done
openssl ecparam -name prime256v1 -genkey -noout | \
    openssl pkcs8 -topk8 -nocrypt -out "$WORK/other-key.pem"

# $1 key  $2 subject  $3 out  $4 issuer cert  $5 issuer key  $6 ext  $7 serial
sign() {
    openssl req -new -key "$1" -subj "$2" -out "$WORK/req.pem"
    openssl x509 -req -in "$WORK/req.pem" -CA "$4" -CAkey "$5" \
        -set_serial "$7" -days $DAYS -sha256 -extfile "$WORK/ext.cnf" \
        -extensions "$6" -out "$3"
}

# $1 key  $2 subject  $3 out
self_sign() {
    openssl req -new -x509 -key "$1" -subj "$2" -set_serial 1 -days $DAYS \
        -sha256 -config "$WORK/ext.cnf" -extensions root -out "$3"
}

self_sign root-key.pem "/C=US/O=wolfSSL/OU=AKID Serial/CN=AKID Serial Root" \
    root-cert.pem
sign ca-key.pem "$CA_SUBJ" ca-cert.pem root-cert.pem root-key.pem ca 0x8A11
sign ca-key.pem "$CA_SUBJ" ca-twin-cert.pem root-cert.pem root-key.pem ca \
    0x2BAD

# An issuer of the CA with another name, only to set the AKID issuer.
self_sign "$WORK/other-key.pem" \
    "/C=US/O=wolfSSL/OU=AKID Serial/CN=AKID Serial Other Root" \
    "$WORK/other-root.pem"
sign ca-key.pem "$CA_SUBJ" "$WORK/ca-other.pem" "$WORK/other-root.pem" \
    "$WORK/other-key.pem" ca 0x8A11

LEAF_SUBJ="/C=US/O=wolfSSL/OU=AKID Serial/CN=localhost"
sign leaf-key.pem "$LEAF_SUBJ" leaf-cert.pem ca-cert.pem ca-key.pem leaf 0x101
sign leaf-key.pem "$LEAF_SUBJ" leaf-twin-cert.pem ca-twin-cert.pem ca-key.pem \
    leaf 0x102
sign leaf-key.pem "$LEAF_SUBJ" leaf-issuer-cert.pem "$WORK/ca-other.pem" \
    ca-key.pem leaf 0x103

# A CA of another key with the serial in the AKID of leaf-otherkey-cert.pem.
openssl ecparam -name prime256v1 -genkey -noout | \
    openssl pkcs8 -topk8 -nocrypt -out "$WORK/otherca-key.pem"
sign "$WORK/otherca-key.pem" "$CA_SUBJ" ca-otherkey-cert.pem root-cert.pem \
    root-key.pem ca 0x3C3C
sign ca-key.pem "$CA_SUBJ" "$WORK/ca-3c3c.pem" root-cert.pem root-key.pem ca \
    0x3C3C
sign leaf-key.pem "$LEAF_SUBJ" leaf-otherkey-cert.pem "$WORK/ca-3c3c.pem" \
    ca-key.pem leaf 0x104
