#!/usr/bin/env bash
#
# gen-alt-chain-forged-ca.sh
# Generate the forged-CA alternate chain test certs.
#
# realRoot     trusted anchor, CN=Root, fixed SKID DEADBEEF...
# evilRoot     attacker key with the same name and SKID as realRoot. Only
#              used to sign attackerCA; never sent or trusted.
# attackerCA   CA issued by evilRoot. Its issuer name and AKID point at
#              realRoot, so the peer finds realRoot as signer but the
#              signature does not verify.
# intermediate unrelated self-signed CA, gives ASN_SELF_SIGNED_E which the
#              alternate cert chain code bypasses.
# leaf         issued by attackerCA.
#
# server-chain.pem is sent as: leaf, intermediate, attackerCA. Only it,
# realRoot-cert.pem and leaf-key.pem (the server's key) are kept. All other
# keys and certs are made fresh in a temp dir and removed once the chain is
# made.

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -f "$WORK"/*; rmdir "$WORK"' EXIT

cat > "$WORK/ext.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
[root]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = DE:AD:BE:EF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:leaf.example.com
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
CNF

# $1 key-path  $2 out
root(){
    openssl req -new -x509 -key "$1" -subj "/O=Test/CN=Root" \
        -days 7300 -sha256 -set_serial 1 -config "$WORK/ext.cnf" \
        -extensions root -out "$2"
}

# $1 key-path  $2 CN  $3 issuer-cert  $4 issuer-key-path  $5 ext  $6 out  $7 serial
child(){
    openssl req -new -key "$1" -subj "/O=Test/CN=$2" \
        -config "$WORK/ext.cnf" -out "$WORK/c.csr"
    openssl x509 -req -in "$WORK/c.csr" -CA "$3" -CAkey "$4" \
        -set_serial "$7" -days 7300 -sha256 -extfile "$WORK/ext.cnf" \
        -extensions "$5" -out "$6"
}

for k in realRoot evilRoot attackerCA intermediate; do
    openssl genrsa -out "$WORK/$k-key.pem" 2048
done
openssl genrsa -out "$DIR/leaf-key.pem" 2048

root "$WORK/realRoot-key.pem" "$DIR/realRoot-cert.pem"
root "$WORK/evilRoot-key.pem" "$WORK/evilRoot-cert.pem"
child "$WORK/attackerCA-key.pem" Attacker "$WORK/evilRoot-cert.pem" \
    "$WORK/evilRoot-key.pem" ca "$WORK/attackerCA-cert.pem" 2
openssl req -new -x509 -key "$WORK/intermediate-key.pem" \
    -subj "/O=Test/CN=Intermediate" -days 7300 -sha256 -set_serial 3 \
    -config "$WORK/ext.cnf" -extensions ca -out "$WORK/intermediate-cert.pem"
child "$DIR/leaf-key.pem" leaf.example.com "$WORK/attackerCA-cert.pem" \
    "$WORK/attackerCA-key.pem" leaf "$WORK/leaf-cert.pem" 4

cat "$WORK/leaf-cert.pem" "$WORK/intermediate-cert.pem" \
    "$WORK/attackerCA-cert.pem" > "$DIR/server-chain.pem"
echo "Done"
