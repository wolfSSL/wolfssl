# Serial Number 0 Test Certificates

This directory contains test certificates for testing wolfSSL's handling of serial number 0 in certificates, specifically for issue #8615.

## Background

RFC 5280 section 4.1.2.2 requires certificate serial numbers to be positive non-zero integers. However, some legacy root CA certificates in real-world trust stores have serial number 0. Since root CAs are explicitly trusted by configuration (not by chain validation), wolfSSL allows serial 0 specifically for self-signed CA certificates (root CAs) while still enforcing RFC 5280 compliance for other certificate types.

## Test Certificates

This directory contains the following test certificates:

### 1. root_serial0.pem
- **Type**: Root CA (self-signed, CA:TRUE)
- **Serial Number**: 0
- **Expected Behavior**: Should be accepted by wolfSSL
- **Purpose**: Tests that legacy root CAs with serial 0 can be loaded

### 2. root.pem
- **Type**: Root CA (self-signed, CA:TRUE)
- **Serial Number**: 1
- **Expected Behavior**: Should be accepted by wolfSSL
- **Purpose**: Normal root CA for signing test certificates

### 3. ee_serial0.pem
- **Type**: End-entity certificate (CA:FALSE)
- **Serial Number**: 0
- **Signed By**: root.pem (serial 1)
- **Expected Behavior**: Should be rejected by wolfSSL
- **Purpose**: Tests that end-entity certs with serial 0 are still rejected

### 4. ee_normal.pem
- **Type**: End-entity certificate (CA:FALSE)
- **Serial Number**: 100
- **Signed By**: root_serial0.pem (serial 0)
- **Expected Behavior**: Should be accepted by wolfSSL
- **Purpose**: Tests that normal certificates signed by a serial 0 root CA work correctly

### 5. selfsigned_nonca_serial0.pem
- **Type**: Self-signed certificate (CA:FALSE)
- **Serial Number**: 0
- **Expected Behavior**: Should be rejected by wolfSSL
- **Purpose**: Tests that self-signed non-CA certs with serial 0 are rejected (only root CAs get the exception)

## Regenerating Certificates

To regenerate all test certificates:

```bash
cd certs/test-serial0
./generate_certs.sh
```

Requirements:
- OpenSSL command-line tool

## Unit Tests

These certificates are used by the `test_SerialNumber0_RootCA()` function in `tests/api/test_asn.c`.

## Related Issues

- GitHub Issue: https://github.com/wolfSSL/wolfssl/issues/8615
- RFC 5280 Section 4.1.2.2: Certificate Serial Number Requirements
- RFC Errata 3200: Clarification that serial numbers must be non-zero

