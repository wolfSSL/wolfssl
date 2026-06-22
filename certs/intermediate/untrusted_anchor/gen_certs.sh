#!/bin/bash

# Regenerate the certificate set used by test_X509_verify_cert_untrusted_inter
# (tests/api/test_ossl_x509_str.c).
#
# The set lets the test verify an end-entity certificate together with
# caller-supplied untrusted intermediates through the OpenSSL compatibility
# path (X509_STORE_CTX_init "chain" argument + X509_verify_cert) and check that
# such a chain is accepted only when it terminates at a trusted anchor.
#
# Two trust chains are produced (both end-entities use the same hostname so a
# downstream hostname check is meaningful):
#
#   single intermediate : leaf      <- int-ca           <- root-ca
#   two intermediates   : leaf-deep <- int-ca2 <- int-ca <- root-ca
#
# Plus:
#   alt-ca               an unrelated self-signed root (a populated but wrong
#                        trust anchor)
#   int-ca-tampered      int-ca with the final byte of its signatureValue
#                        flipped (valid TBSCertificate, broken outer signature)
#
# The certificates intentionally omit subjectKeyIdentifier /
# authorityKeyIdentifier; the test relies on this, so the script aborts at the
# end if they were added back.  OpenSSL 3.x adds them automatically with no
# option to suppress them, so regenerate with a tool that does not (e.g.
# OPENSSL=/usr/bin/openssl on macOS).
#
# RSA-2048 / SHA-256, ~30 year validity so the regression does not expire.
#
# Requires: openssl (or a compatible LibreSSL, see above) and python3 (used to
# flip a signature byte for the tampered intermediate).  With set -e a missing
# python3 aborts regeneration partway through, leaving a half-written fixture
# set; install python3 (or replace the byte-flip step) before regenerating.

set -e
cd "$(dirname "$0")"

OPENSSL="${OPENSSL:-openssl}"
DAYS=10957
RSA_BITS=2048

CA_EXT=$(mktemp)
LEAF_EXT=$(mktemp)
trap 'rm -f "$CA_EXT" "$LEAF_EXT" *.csr *.srl' EXIT

# No pathlen so the first intermediate can still issue the second one in the
# two-intermediate positive control; no key identifiers (see header).
cat > "$CA_EXT" <<'EOF'
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
EOF

cat > "$LEAF_EXT" <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:www.example.test
EOF

genkey() { "$OPENSSL" genrsa -out "$1" "$RSA_BITS" 2>/dev/null; }

# Self-sign a root CA: genroot <key> <cert> <CN>
genroot() {
    "$OPENSSL" req -x509 -new -key "$1" -sha256 -subj "/CN=$3" -days "$DAYS" \
        -extensions v3 \
        -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n%s' \
            "$(cat "$CA_EXT")") \
        -out "$2"
}

# Sign a CSR: signcert <csr> <cert> <issuer-cert> <issuer-key> <extfile>
signcert() {
    "$OPENSSL" x509 -req -in "$1" -CA "$3" -CAkey "$4" -CAcreateserial \
        -sha256 -days "$DAYS" -extfile "$5" -out "$2" 2>/dev/null
}

# Roots ----------------------------------------------------------------------
genkey root-ca-key.pem
genroot root-ca-key.pem root-ca-cert.pem "wolfSSL Untrusted-Anchor Test Root"

genkey alt-ca-key.pem
genroot alt-ca-key.pem alt-ca-cert.pem "wolfSSL Untrusted-Anchor Test Alt Root"

# Intermediate signed by the root --------------------------------------------
genkey int-ca-key.pem
"$OPENSSL" req -new -key int-ca-key.pem -sha256 \
    -subj "/CN=wolfSSL Untrusted-Anchor Test Intermediate" -out int-ca.csr
signcert int-ca.csr int-ca-cert.pem root-ca-cert.pem root-ca-key.pem "$CA_EXT"

# Leaf signed by the intermediate (single-intermediate chain) ----------------
genkey leaf-key.pem
"$OPENSSL" req -new -key leaf-key.pem -sha256 \
    -subj "/CN=www.example.test" -out leaf.csr
signcert leaf.csr leaf-cert.pem int-ca-cert.pem int-ca-key.pem "$LEAF_EXT"

# Second-level intermediate signed by the first intermediate -----------------
genkey int-ca2-key.pem
"$OPENSSL" req -new -key int-ca2-key.pem -sha256 \
    -subj "/CN=wolfSSL Untrusted-Anchor Test Intermediate 2" -out int-ca2.csr
signcert int-ca2.csr int-ca2-cert.pem int-ca-cert.pem int-ca-key.pem "$CA_EXT"

# Leaf signed by the second-level intermediate (two-intermediate chain) ------
genkey leaf-deep-key.pem
"$OPENSSL" req -new -key leaf-deep-key.pem -sha256 \
    -subj "/CN=www.example.test" -out leaf-deep.csr
signcert leaf-deep.csr leaf-deep-cert.pem int-ca2-cert.pem int-ca2-key.pem \
    "$LEAF_EXT"

# Tampered intermediate: flip the final byte of the DER (last byte of the
# signatureValue) so the TBSCertificate stays valid but the outer signature no
# longer verifies.
"$OPENSSL" x509 -in int-ca-cert.pem -outform DER -out int-ca.der
python3 - <<'PY'
d = open("int-ca.der", "rb").read()
d = d[:-1] + bytes([d[-1] ^ 0x01])
open("int-ca-tampered.der", "wb").write(d)
PY
"$OPENSSL" x509 -inform DER -in int-ca-tampered.der -out int-ca-tampered-cert.pem
rm -f int-ca.der int-ca-tampered.der

# Guard: these test certificates must not carry key identifiers (see header).
for c in root-ca-cert.pem alt-ca-cert.pem int-ca-cert.pem int-ca2-cert.pem \
         leaf-cert.pem leaf-deep-cert.pem; do
    if "$OPENSSL" x509 -in "$c" -noout -text \
            | grep -q "Key Identifier"; then
        echo "ERROR: $c carries a subject/authority key identifier." >&2
        echo "Use an OpenSSL/LibreSSL that does not auto-add them" >&2
        echo "(e.g. OPENSSL=/usr/bin/openssl $0)." >&2
        exit 1
    fi
done

echo "Completed"
