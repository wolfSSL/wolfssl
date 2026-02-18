#!/usr/bin/env python3
"""Fix SM2 certificate SubjectPublicKeyInfo algorithm OID.

OpenSSL 3.x encodes SM2 keys using the generic id-ecPublicKey OID
(1.2.840.10045.2.1) instead of the SM2-specific OID (1.2.156.10197.1.301).
This script patches the SPKI algorithm OID back to SM2 and re-signs the
certificate.

Usage: fix_sm2_spki.py <cert.pem> <signing-key.pem> <output.pem>
"""

import base64
import subprocess
import sys
import os
import tempfile

EC_PUBKEY_OID = bytes([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
SM2_ALGO_OID  = bytes([0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d])
SM2_WITH_SM3  = bytes([0x30, 0x0a, 0x06, 0x08,
                       0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75])


def read_der_length(data, offset):
    b = data[offset]
    if b < 0x80:
        return b, 1
    num_bytes = b & 0x7f
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + 1 + i]
    return length, 1 + num_bytes


def encode_der_length(length):
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, length >> 8, length & 0xff])
    else:
        raise ValueError("Length too large: %d" % length)


def find_enclosing_sequences(data, target_pos):
    """Find length-field offsets of all SEQUENCEs enclosing target_pos."""
    results = []

    def scan(offset, end):
        while offset < end:
            tag = data[offset]
            offset += 1
            length, len_bytes = read_der_length(data, offset)
            len_offset = offset
            offset += len_bytes
            content_start = offset
            content_end = offset + length

            if tag == 0x30 and content_start <= target_pos < content_end:
                results.append((len_offset, length, len_bytes))
                scan(content_start, content_end)
                return
            offset = content_end

    scan(0, len(data))
    return results


def patch_tbs_spki_oid(tbs_der):
    """Replace id-ecPublicKey with SM2 OID in TBS SubjectPublicKeyInfo."""
    oid_pos = tbs_der.find(EC_PUBKEY_OID)
    if oid_pos == -1:
        return None  # Already has SM2 OID or no EC key

    enclosing = find_enclosing_sequences(tbs_der, oid_pos)
    size_diff = len(SM2_ALGO_OID) - len(EC_PUBKEY_OID)

    result = bytearray(
        tbs_der[:oid_pos] + SM2_ALGO_OID + tbs_der[oid_pos + len(EC_PUBKEY_OID):]
    )

    for len_offset, old_length, old_len_bytes in enclosing:
        new_length = old_length + size_diff
        new_len_encoded = encode_der_length(new_length)
        if len(new_len_encoded) == old_len_bytes:
            result[len_offset:len_offset + old_len_bytes] = new_len_encoded
        else:
            result[len_offset:len_offset + old_len_bytes] = new_len_encoded
            size_diff += len(new_len_encoded) - old_len_bytes

    return bytes(result)


def pem_to_der(pem_text):
    b64 = ''.join(
        line for line in pem_text.split('\n')
        if not line.startswith('-----') and line.strip()
    )
    return base64.b64decode(b64)


def der_to_pem(der_data, label="CERTIFICATE"):
    b64 = base64.b64encode(der_data).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return ('-----BEGIN %s-----\n' % label +
            '\n'.join(lines) +
            '\n-----END %s-----\n' % label)


def extract_tbs(cert_der):
    assert cert_der[0] == 0x30
    outer_len, outer_len_bytes = read_der_length(cert_der, 1)
    tbs_offset = 1 + outer_len_bytes
    tbs_len, tbs_len_bytes = read_der_length(cert_der, tbs_offset + 1)
    tbs_total = 1 + tbs_len_bytes + tbs_len
    return cert_der[tbs_offset:tbs_offset + tbs_total]


def sign_tbs(tbs_der, key_pem_path):
    """Sign TBS with SM2-with-SM3 using openssl dgst."""
    with tempfile.NamedTemporaryFile(suffix='.der', delete=False) as tbs_f:
        tbs_f.write(tbs_der)
        tbs_path = tbs_f.name

    sig_path = tbs_path + '.sig'
    try:
        result = subprocess.run(
            ['openssl', 'dgst', '-sm3', '-sign', key_pem_path,
             '-out', sig_path, tbs_path],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError("openssl dgst failed: " + result.stderr)

        with open(sig_path, 'rb') as f:
            return f.read()
    finally:
        os.unlink(tbs_path)
        if os.path.exists(sig_path):
            os.unlink(sig_path)


def build_cert(tbs_der, sig_der):
    bit_string = bytes([0x03, len(sig_der) + 1, 0x00]) + sig_der
    cert_body = tbs_der + SM2_WITH_SM3 + bit_string
    return bytes([0x30]) + encode_der_length(len(cert_body)) + cert_body


def fix_sm2_cert(cert_pem_path, key_pem_path, output_pem_path):
    with open(cert_pem_path, 'r') as f:
        cert_pem = f.read()

    cert_der = pem_to_der(cert_pem)
    tbs = extract_tbs(cert_der)

    new_tbs = patch_tbs_spki_oid(tbs)
    if new_tbs is None:
        print("  Already has SM2 OID, no patching needed")
        if cert_pem_path != output_pem_path:
            with open(output_pem_path, 'w') as f:
                f.write(cert_pem)
        return

    sig = sign_tbs(new_tbs, key_pem_path)
    new_cert_der = build_cert(new_tbs, sig)

    with open(output_pem_path, 'w') as f:
        f.write(der_to_pem(new_cert_der))

    print("  Patched SPKI algorithm OID to SM2")


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: %s <cert.pem> <signing-key.pem> <output.pem>" % sys.argv[0])
        sys.exit(1)

    fix_sm2_cert(sys.argv[1], sys.argv[2], sys.argv[3])
