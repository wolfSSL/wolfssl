#!/usr/bin/env bash
#
# gen-nc-ancestor-csr2.sh
# CSR2 variant of the NameConstraints ancestor-walk certs: the
# constrained ancestor shares the trust anchor's DN but reaches the
# client only through the CSR2 pool. Commits only the root cert,
# leaf chain, and leaf key; the rest is scratch.

set -e

check_result(){
    if [ $1 -ne 0 ]; then
        echo "$2 Failed, Abort"
        exit 1
    else
        echo "$2 Succeeded!"
    fi
}

DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Issue a child cert from $issuer_cert/$issuer_key.
# $1 child-key  $2 subject-CN  $3 out-cert  $4 ext-file  $5 ext-section  $6 serial
mkchild(){
    local child_key=$1 cn=$2 out=$3 extfile=$4 extsec=$5 serial=$6
    openssl req -new -key "$child_key" -out "$WORK/child.csr" \
        -subj "/C=US/O=NC Tests/CN=$cn" -config "$extfile"
    check_result $? "$(basename "$out"): csr"
    openssl x509 -req -in "$WORK/child.csr" \
        -CA "$issuer_cert" -CAkey "$issuer_key" \
        -set_serial "$serial" -out "$out" -days 7300 -sha256 \
        -extfile "$extfile" -extensions "$extsec"
    check_result $? "$(basename "$out"): sign"
    rm -f "$WORK/child.csr"
}

# ---- ext configs ----

cat > "$WORK/root.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat > "$WORK/strict-ca.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
[v3_strict]
basicConstraints = critical, CA:TRUE, pathlen:1
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
nameConstraints = critical, permitted;URI:.example.com
EOF

cat > "$WORK/intermediate-noakid.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
[v3_inter]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

cat > "$WORK/leaf-attacker.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
[v3_leaf_attacker]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
subjectAltName = critical, URI:https://attacker.com/leaf
EOF

# ---- csr2-root (self-signed, the only thing the client trusts) ----

openssl genrsa -out "$WORK/csr2-root-key.pem" 2048 2>/dev/null
check_result $? "csr2-root-key.pem"
openssl req -new -x509 -key "$WORK/csr2-root-key.pem" \
    -out "$DIR/csr2-root-cert.pem" \
    -subj "/C=US/O=NC Tests/CN=CSR2 NC Root" \
    -config "$WORK/root.cnf" -extensions v3_ca \
    -set_serial 0x40 -days 7300 -sha256
check_result $? "csr2-root-cert.pem"

# ---- csr2-strict-ca: same DN as root, different key, issued by root ----

openssl genrsa -out "$WORK/csr2-strict-ca-key.pem" 2048 2>/dev/null
check_result $? "csr2-strict-ca-key.pem"
openssl req -new -key "$WORK/csr2-strict-ca-key.pem" \
    -out "$WORK/strict-ca.csr" \
    -subj "/C=US/O=NC Tests/CN=CSR2 NC Root" -config "$WORK/strict-ca.cnf"
check_result $? "csr2-strict-ca-cert.pem: csr"
openssl x509 -req -in "$WORK/strict-ca.csr" \
    -CA "$DIR/csr2-root-cert.pem" -CAkey "$WORK/csr2-root-key.pem" \
    -set_serial 0x41 -out "$WORK/csr2-strict-ca-cert.pem" -days 7300 -sha256 \
    -extfile "$WORK/strict-ca.cnf" -extensions v3_strict
check_result $? "csr2-strict-ca-cert.pem: sign"

# ---- csr2-intermediate: issued by strict-ca, no AKID extension ----

openssl genrsa -out "$WORK/csr2-intermediate-key.pem" 2048 2>/dev/null
check_result $? "csr2-intermediate-key.pem"
issuer_cert="$WORK/csr2-strict-ca-cert.pem"
issuer_key="$WORK/csr2-strict-ca-key.pem"
mkchild "$WORK/csr2-intermediate-key.pem" "CSR2 NC Intermediate" \
    "$WORK/csr2-intermediate-cert.pem" "$WORK/intermediate-noakid.cnf" \
    v3_inter 0x50

# ---- csr2-leaf-attacker: issued by the no-AKID intermediate ----

openssl genrsa -out "$DIR/csr2-leaf-attacker-key.pem" 2048 2>/dev/null
check_result $? "csr2-leaf-attacker-key.pem"
issuer_cert="$WORK/csr2-intermediate-cert.pem"
issuer_key="$WORK/csr2-intermediate-key.pem"
mkchild "$DIR/csr2-leaf-attacker-key.pem" "CSR2 NC Attacker Leaf" \
    "$WORK/csr2-leaf-attacker-cert.pem" "$WORK/leaf-attacker.cnf" \
    v3_leaf_attacker 0x60

# ---- Concatenated server chain: leaf + no-AKID intermediate + strict-ca ----

cat "$WORK/csr2-leaf-attacker-cert.pem" \
    "$WORK/csr2-intermediate-cert.pem" \
    "$WORK/csr2-strict-ca-cert.pem" \
    > "$DIR/csr2-leaf-chain.pem"
check_result $? "csr2-leaf-chain.pem"

echo "Generated CSR2 NC ancestor chain in $DIR/"
ls -la "$DIR"/csr2-*
