#!/bin/bash
#
# Generate test certificates for serial number 0 testing (issue #8615)
#
# Tests verify that root CAs (self-signed + CA:TRUE) with serial 0 are
# accepted, whether loaded as trust anchors or received in a peer's chain
# (issue #11952), while all other cert types with serial 0 are rejected
# per RFC 5280 section 4.1.2.2.
#
# Output files (keys are kept only where a test needs them):
#   root_serial0.pem / root_serial0_key.pem  - Root CA with serial 0
#   ee_serial0.pem                           - EE cert with serial 0 (rejected)
#   ee_serial0_expired.pem                   - Expired EE cert with serial 0
#                                              (rejected, not a date error;
#                                              needs OpenSSL 3.4 or later)
#   ee_normal.pem / ee_normal_key.pem        - Normal EE cert (serial 100)
#   ee_normal_chain.pem                      - ee_normal + root_serial0, a
#                                              server chain ending in the
#                                              serial 0 root
#   selfsigned_nonca_serial0.pem             - Self-signed non-CA, serial 0
#   intermediate_serial0.pem                 - Intermediate CA, serial 0
#                                              (CA:TRUE but issuer != subject)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==================================================="
echo "Generating serial 0 test certificates in: $SCRIPT_DIR"
echo "==================================================="

# 1. Create Root CA with serial number 0
echo ""
echo "[1/7] Creating Root CA with serial number 0..."
openssl req -x509 -newkey rsa:2048 -keyout root_serial0_key.pem -out root_serial0.pem \
    -days 7300 -nodes -subj "/CN=Test Root CA Serial 0/O=wolfSSL Test/C=US" \
    -set_serial 0 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "   Root CA serial number:"
openssl x509 -in root_serial0.pem -noout -serial

# 2. Create end-entity cert with serial 0 signed by root_serial0
echo ""
echo "[2/7] Creating end-entity certificate with serial number 0..."
openssl req -newkey rsa:2048 -keyout ee_serial0_key.tmp -out ee_serial0.csr.tmp -nodes \
    -subj "/CN=End Entity Serial 0/O=wolfSSL Test/C=US"

openssl x509 -req -in ee_serial0.csr.tmp -CA root_serial0.pem -CAkey root_serial0_key.pem \
    -out ee_serial0.pem -days 3650 -set_serial 0 \
    -extfile <(echo "basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth")

rm -f ee_serial0_key.tmp ee_serial0.csr.tmp

echo "   End-entity cert serial number:"
openssl x509 -in ee_serial0.pem -noout -serial

# 3. Create normal end-entity cert signed by root CA with serial 0
echo ""
echo "[3/7] Creating normal end-entity certificate (signed by serial 0 root)..."
openssl req -newkey rsa:2048 -keyout ee_normal_key.pem -out ee_normal.csr.tmp -nodes \
    -subj "/CN=End Entity Normal/O=wolfSSL Test/C=US"

openssl x509 -req -in ee_normal.csr.tmp -CA root_serial0.pem -CAkey root_serial0_key.pem \
    -out ee_normal.pem -days 3650 -set_serial 100 \
    -extfile <(echo "basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth")

rm -f ee_normal.csr.tmp

echo "   Normal end-entity cert serial number:"
openssl x509 -in ee_normal.pem -noout -serial

# 4. Create self-signed non-CA certificate with serial 0
echo ""
echo "[4/7] Creating self-signed non-CA certificate with serial number 0..."
openssl req -x509 -newkey rsa:2048 -keyout selfsigned_nonca_serial0_key.tmp \
    -out selfsigned_nonca_serial0.pem -days 3650 -nodes \
    -subj "/CN=Self-Signed Non-CA Serial 0/O=wolfSSL Test/C=US" \
    -set_serial 0 \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=digitalSignature,keyEncipherment"

rm -f selfsigned_nonca_serial0_key.tmp

echo "   Self-signed non-CA cert serial number:"
openssl x509 -in selfsigned_nonca_serial0.pem -noout -serial

# 5. Create intermediate CA cert with serial 0, signed by root_serial0
#    (CA:TRUE but issuer != subject, so cert->selfIssued will be 0).
echo ""
echo "[5/7] Creating intermediate CA certificate with serial number 0..."
openssl req -newkey rsa:2048 -keyout intermediate_serial0_key.tmp \
    -out intermediate_serial0.csr.tmp -nodes \
    -subj "/CN=Intermediate CA Serial 0/O=wolfSSL Test/C=US"

openssl x509 -req -in intermediate_serial0.csr.tmp \
    -CA root_serial0.pem -CAkey root_serial0_key.pem \
    -out intermediate_serial0.pem -days 3650 -set_serial 0 \
    -extfile <(echo "basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign")

rm -f intermediate_serial0_key.tmp intermediate_serial0.csr.tmp

echo "   Intermediate CA cert serial number:"
openssl x509 -in intermediate_serial0.pem -noout -serial

# 6. Server chain that ends in the serial 0 root. A TLS test presents it
#    from the server side so the client receives the root as a chain
#    certificate (CHAIN_CERT_TYPE), the way the Go Daddy and Starfield
#    bundles are deployed (issue #11952).
echo ""
echo "[6/7] Creating server chain ending in the serial 0 root..."
cat ee_normal.pem root_serial0.pem > ee_normal_chain.pem

echo "   Chain certificates:"
grep -c "BEGIN CERTIFICATE" ee_normal_chain.pem

# 7. Expired end-entity cert with serial 0. Parsed with VERIFY it must fail
#    on the serial, not on the date, which a verify callback may accept.
#    -not_before/-not_after need OpenSSL 3.4 or later.
echo ""
echo "[7/7] Creating expired end-entity certificate with serial number 0..."
openssl req -newkey rsa:2048 -keyout ee_serial0_expired_key.tmp \
    -out ee_serial0_expired.csr.tmp -nodes \
    -subj "/CN=End Entity Serial 0 Expired/O=wolfSSL Test/C=US"

openssl x509 -req -in ee_serial0_expired.csr.tmp \
    -CA root_serial0.pem -CAkey root_serial0_key.pem \
    -out ee_serial0_expired.pem -set_serial 0 \
    -not_before 20200101000000Z -not_after 20210101000000Z \
    -extfile <(echo "basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth")

rm -f ee_serial0_expired_key.tmp ee_serial0_expired.csr.tmp

echo "   Expired end-entity cert dates:"
openssl x509 -in ee_serial0_expired.pem -noout -serial -dates

echo ""
echo "==================================================="
echo "Certificate generation complete!"
echo "==================================================="
