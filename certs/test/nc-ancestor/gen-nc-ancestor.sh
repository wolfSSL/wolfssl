#!/usr/bin/env bash
#
# gen-nc-ancestor.sh
# Re-sign the NameConstraints ancestor-walk test certs from committed
# keys. Cert SKIDs are stable across runs; 01-uri-permit-ca and its
# permissive sibling are pinned to satisfy the AKID-disambiguation test.

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

cat > "$WORK/uri-permit-ca.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
[v3_uri_permit]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
nameConstraints = critical, permitted;URI:.example.com
EOF

cat > "$WORK/sub-ca-nonc.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
[v3_sub_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
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
authorityKeyIdentifier = keyid
subjectAltName = critical, URI:https://attacker.com/leaf
EOF

cat > "$WORK/leaf-valid.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
[v3_leaf_valid]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = critical, URI:https://benign.example.com/
EOF

# ---- 00 root (self-signed) ----

openssl req -new -x509 -key "$DIR/00-root-key.pem" \
    -out "$DIR/00-root-cert.pem" \
    -subj "/C=US/O=NC Tests/CN=NC Test Root" \
    -config "$WORK/root.cnf" -extensions v3_ca \
    -set_serial 0x10 -days 7300 -sha256
check_result $? "00-root-cert.pem"

# ---- 01 uri-permit-ca (permits URI:.example.com), issued by root ----

issuer_cert="$DIR/00-root-cert.pem"
issuer_key="$DIR/00-root-key.pem"
mkchild "$DIR/01-uri-permit-ca-key.pem" "URI Permit CA" \
    "$DIR/01-uri-permit-ca-cert.pem" "$WORK/uri-permit-ca.cnf" \
    v3_uri_permit 0x11

# ---- 00 uri-permit-ca-permissive (same-DN distractor, self-signed) ----

openssl req -new -x509 -key "$DIR/00-uri-permit-ca-permissive-key.pem" \
    -out "$DIR/00-uri-permit-ca-permissive-cert.pem" \
    -subj "/C=US/O=NC Tests/CN=URI Permit CA" \
    -config "$WORK/root.cnf" -extensions v3_ca \
    -set_serial 0x12 -days 7300 -sha256
check_result $? "00-uri-permit-ca-permissive-cert.pem"

# ---- 02 benign-sub-ca (no NC), issued by uri-permit-ca ----

issuer_cert="$DIR/01-uri-permit-ca-cert.pem"
issuer_key="$DIR/01-uri-permit-ca-key.pem"
mkchild "$DIR/02-benign-sub-ca-key.pem" "Benign Sub CA" \
    "$DIR/02-benign-sub-ca-cert.pem" "$WORK/sub-ca-nonc.cnf" \
    v3_sub_ca 0x20

# ---- 03 leaf-attacker (URI violates grandparent's permit), issued by sub-ca ----

issuer_cert="$DIR/02-benign-sub-ca-cert.pem"
issuer_key="$DIR/02-benign-sub-ca-key.pem"
mkchild "$DIR/03-leaf-attacker-key.pem" "NC Test Attacker Leaf" \
    "$WORK/03-leaf-cert.pem" "$WORK/leaf-attacker.cnf" \
    v3_leaf_attacker 0x30

# ---- 03 valid-leaf (URI inside permit), issued by sub-ca ----

mkchild "$DIR/03-valid-leaf-key.pem" "NC Test Valid Leaf" \
    "$DIR/03-valid-leaf-cert.pem" "$WORK/leaf-valid.cnf" \
    v3_leaf_valid 0x31

# ---- Concatenated bundle: attacker leaf + benign-sub-ca + uri-permit-ca ----

cat "$WORK/03-leaf-cert.pem" \
    "$DIR/02-benign-sub-ca-cert.pem" \
    "$DIR/01-uri-permit-ca-cert.pem" \
    > "$DIR/03-leaf-chain.pem"
check_result $? "03-leaf-chain.pem"

echo "Generated chain in $DIR/"
ls -la "$DIR/"
