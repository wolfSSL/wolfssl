#!/bin/bash
#
# Generate test certificates for serial number 0 testing (issue #8615)
# This script creates certificates in the certs/test-serial0/ directory

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==================================================="
echo "Generating serial 0 test certificates in: $SCRIPT_DIR"
echo "==================================================="

# 1. Create Root CA with serial number 0
echo ""
echo "[1/5] Creating Root CA with serial number 0..."
openssl req -x509 -newkey rsa:2048 -keyout root_serial0_key.pem -out root_serial0.pem \
    -days 7300 -nodes -subj "/CN=Test Root CA Serial 0/O=wolfSSL Test/C=US" \
    -set_serial 0 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "   Root CA serial number:"
openssl x509 -in root_serial0.pem -noout -serial

# 2. Create normal Root CA (serial != 0)
echo ""
echo "[2/5] Creating normal Root CA with serial number 1..."
openssl req -x509 -newkey rsa:2048 -keyout root_key.pem -out root.pem \
    -days 7300 -nodes -subj "/CN=Test Root CA Normal/O=wolfSSL Test/C=US" \
    -set_serial 1 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "   Root CA serial number:"
openssl x509 -in root.pem -noout -serial

# 3. Create end-entity cert with serial 0 signed by normal root
echo ""
echo "[3/5] Creating end-entity certificate with serial number 0..."
openssl req -newkey rsa:2048 -keyout ee_serial0_key.pem -out ee_serial0.csr -nodes \
    -subj "/CN=End Entity Serial 0/O=wolfSSL Test/C=US"

openssl x509 -req -in ee_serial0.csr -CA root.pem -CAkey root_key.pem \
    -out ee_serial0.pem -days 3650 -set_serial 0 \
    -extfile <(echo "basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth")

echo "   End-entity cert serial number:"
openssl x509 -in ee_serial0.pem -noout -serial

# 4. Create normal end-entity cert signed by root CA with serial 0
echo ""
echo "[4/5] Creating normal end-entity certificate (signed by serial 0 root)..."
openssl req -newkey rsa:2048 -keyout ee_normal_key.pem -out ee_normal.csr -nodes \
    -subj "/CN=End Entity Normal/O=wolfSSL Test/C=US"

openssl x509 -req -in ee_normal.csr -CA root_serial0.pem -CAkey root_serial0_key.pem \
    -out ee_normal.pem -days 3650 -set_serial 100 \
    -extfile <(echo "basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth")

echo "   Normal end-entity cert serial number:"
openssl x509 -in ee_normal.pem -noout -serial

# 5. Create self-signed non-CA certificate with serial 0
echo ""
echo "[5/5] Creating self-signed non-CA certificate with serial number 0..."
openssl req -x509 -newkey rsa:2048 -keyout selfsigned_nonca_serial0_key.pem \
    -out selfsigned_nonca_serial0.pem -days 3650 -nodes \
    -subj "/CN=Self-Signed Non-CA Serial 0/O=wolfSSL Test/C=US" \
    -set_serial 0 \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=digitalSignature,keyEncipherment"

echo "   Self-signed non-CA cert serial number:"
openssl x509 -in selfsigned_nonca_serial0.pem -noout -serial

echo ""
echo "==================================================="
echo "Certificate generation complete!"
echo "==================================================="
echo ""
echo "Generated certificates in: $SCRIPT_DIR"
echo "  - root_serial0.pem         (Root CA with serial 0)"
echo "  - root.pem                 (Normal root CA)"
echo "  - ee_serial0.pem           (End-entity with serial 0)"
echo "  - ee_normal.pem            (Normal end-entity)"
echo "  - selfsigned_nonca_serial0.pem (Self-signed non-CA with serial 0)"
echo ""

