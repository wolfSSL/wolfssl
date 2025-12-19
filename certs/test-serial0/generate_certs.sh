#!/bin/bash
#
# Generate test certificates for serial number 0 testing (issue #8615)
#
# Tests verify that root CAs (self-signed + CA:TRUE) with serial 0 are
# accepted as trust anchors, while all other cert types with serial 0
# are rejected per RFC 5280 section 4.1.2.2.
#
# Output files (certs only -- EE keys use temp files):
#   root_serial0.pem / root_serial0_key.pem  - Root CA with serial 0
#   ee_serial0.pem                           - EE cert with serial 0 (rejected)
#   ee_normal.pem                            - Normal EE cert (serial 100)
#   selfsigned_nonca_serial0.pem             - Self-signed non-CA, serial 0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==================================================="
echo "Generating serial 0 test certificates in: $SCRIPT_DIR"
echo "==================================================="

# 1. Create Root CA with serial number 0
echo ""
echo "[1/4] Creating Root CA with serial number 0..."
openssl req -x509 -newkey rsa:2048 -keyout root_serial0_key.pem -out root_serial0.pem \
    -days 7300 -nodes -subj "/CN=Test Root CA Serial 0/O=wolfSSL Test/C=US" \
    -set_serial 0 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "   Root CA serial number:"
openssl x509 -in root_serial0.pem -noout -serial

# 2. Create end-entity cert with serial 0 signed by root_serial0
echo ""
echo "[2/4] Creating end-entity certificate with serial number 0..."
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
echo "[3/4] Creating normal end-entity certificate (signed by serial 0 root)..."
openssl req -newkey rsa:2048 -keyout ee_normal_key.tmp -out ee_normal.csr.tmp -nodes \
    -subj "/CN=End Entity Normal/O=wolfSSL Test/C=US"

openssl x509 -req -in ee_normal.csr.tmp -CA root_serial0.pem -CAkey root_serial0_key.pem \
    -out ee_normal.pem -days 3650 -set_serial 100 \
    -extfile <(echo "basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth")

rm -f ee_normal_key.tmp ee_normal.csr.tmp

echo "   Normal end-entity cert serial number:"
openssl x509 -in ee_normal.pem -noout -serial

# 4. Create self-signed non-CA certificate with serial 0
echo ""
echo "[4/4] Creating self-signed non-CA certificate with serial number 0..."
openssl req -x509 -newkey rsa:2048 -keyout selfsigned_nonca_serial0_key.tmp \
    -out selfsigned_nonca_serial0.pem -days 3650 -nodes \
    -subj "/CN=Self-Signed Non-CA Serial 0/O=wolfSSL Test/C=US" \
    -set_serial 0 \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=digitalSignature,keyEncipherment"

rm -f selfsigned_nonca_serial0_key.tmp

echo "   Self-signed non-CA cert serial number:"
openssl x509 -in selfsigned_nonca_serial0.pem -noout -serial

echo ""
echo "==================================================="
echo "Certificate generation complete!"
echo "==================================================="
