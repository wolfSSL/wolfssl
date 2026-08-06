#!/usr/bin/env python3
"""
    Generates tests/api/test_x500_unique_id_certs.h, the certificate blobs used
    by test_wc_ParseCert_uniqueIdentifier() in tests/api.c.

    Each certificate is self-signed ECDSA P-256 and carries an
    x500UniqueIdentifier (OID 2.5.4.45) attribute in both the subject and the
    issuer DN. That attribute is encoded as a BIT STRING rather than a
    DirectoryString, which is what the test exercises. pyca/cryptography cannot
    emit a BIT STRING DN attribute, so the TBSCertificate is built with the DER
    helpers below and only the key generation and signing come from
    cryptography.

    The test parses with NO_VERIFY, so the validity dates are never checked and
    the certificates do not need to be renewed when they expire. Adjust
    NOT_BEFORE / NOT_AFTER below if new dates are wanted anyway.

    Every run emits a fresh key and signature, so the byte arrays change even
    when nothing else does. The DN contents the test asserts on (UNIQUE_ID and
    EMBEDDED_NUL_ID) are unaffected.

    Requires: pip install cryptography
    Usage:    python3 ./tests/api/create_x500_unique_id_certs.py
              (run from the top of the wolfSSL source tree)
"""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HEADER_PATH = './tests/api/test_x500_unique_id_certs.h'
HEADER_GUARD = 'WOLFCRYPT_TEST_X500_UNIQUE_ID_CERTS_H'

# UTCTime, YYMMDDHHMMSSZ. 49 maps to 2049 per RFC 5280 4.1.2.5.1.
NOT_BEFORE = '200101000000Z'
NOT_AFTER = '491231000000Z'
SERIAL = 0x0EAF12345678
COUNTRY = 'US'
ORG = 'Test Org'
COMMON_NAME = 'LEAF Test Card'
# Value of the x500UniqueIdentifier BIT STRING, byte aligned (0 unused bits).
UNIQUE_ID = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
# Same, but with an embedded NUL that truncates the subject display string.
EMBEDDED_NUL_ID = bytes([0xAB, 0x00, 0xCD, 0xEF])
# An empty BIT STRING ('03 01 00'), which the parser must reject.
EMPTY_ID = b''

OID_COUNTRY = '2.5.4.6'
OID_ORG = '2.5.4.10'
OID_COMMON_NAME = '2.5.4.3'
OID_X500_UNIQUE_ID = '2.5.4.45'
OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2'

LICENSE = """/* test_x500_unique_id_certs.h
 *
 * This file is generated automatically by running
 * ./tests/api/create_x500_unique_id_certs.py.
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
"""


def tlv(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        length = bytes([len(value)])
    else:
        enc = len(value).to_bytes((len(value).bit_length() + 7) // 8, 'big')
        length = bytes([0x80 | len(enc)]) + enc
    return bytes([tag]) + length + value


def der_sequence(*items: bytes) -> bytes:
    return tlv(0x30, b''.join(items))


def der_set(*items: bytes) -> bytes:
    return tlv(0x31, b''.join(items))


def der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split('.')]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def der_integer(value: int) -> bytes:
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    if body[0] & 0x80:
        body = b'\x00' + body
    return tlv(0x02, body)


def der_printable_string(value: str) -> bytes:
    return tlv(0x13, value.encode('ascii'))


def der_utf8_string(value: str) -> bytes:
    return tlv(0x0C, value.encode('utf-8'))


def der_utc_time(value: str) -> bytes:
    return tlv(0x17, value.encode('ascii'))


def der_bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    return tlv(0x03, bytes([unused_bits]) + data)


def der_explicit(number: int, data: bytes) -> bytes:
    return tlv(0xA0 | number, data)


def rdn(oid: str, value: bytes) -> bytes:
    """A single-valued RelativeDistinguishedName."""
    return der_set(der_sequence(der_oid(oid), value))


def name(unique_id: bytes) -> bytes:
    return der_sequence(
        rdn(OID_COUNTRY, der_printable_string(COUNTRY)),
        rdn(OID_ORG, der_utf8_string(ORG)),
        rdn(OID_COMMON_NAME, der_utf8_string(COMMON_NAME)),
        rdn(OID_X500_UNIQUE_ID, der_bit_string(unique_id)),
    )


def make_cert(unique_id: bytes) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    sig_alg = der_sequence(der_oid(OID_ECDSA_SHA256))
    dn = name(unique_id)
    tbs = der_sequence(
        der_explicit(0, der_integer(2)),  # version v3
        der_integer(SERIAL),
        sig_alg,
        dn,                               # issuer, self-signed
        der_sequence(der_utc_time(NOT_BEFORE), der_utc_time(NOT_AFTER)),
        dn,                               # subject
        spki,
    )
    signature = key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    return der_sequence(tbs, sig_alg, der_bit_string(signature))


def pretty_date(utc_time: str) -> str:
    """YYMMDDHHMMSSZ -> YYYY-MM-DD, per RFC 5280 4.1.2.5.1."""
    year = int(utc_time[0:2])
    year += 1900 if year >= 50 else 2000
    return '%04d-%s-%s' % (year, utc_time[2:4], utc_time[4:6])


def write_buffer(f, comment: str, name: str, data: bytes,
                 blank_after: bool = True) -> None:
    f.write(comment)
    f.write('static const unsigned char %s[] = {\n' % name)
    for i in range(0, len(data), 12):
        f.write('    ' + ', '.join('0x%02X' % b for b in data[i:i + 12]) +
                (',' if i + 12 < len(data) else '') + '\n')
    f.write('};\n')
    if blank_after:
        f.write('\n')


if __name__ == '__main__':
    with open(HEADER_PATH, 'w') as f:
        f.write(LICENSE)
        f.write('\n#ifndef %s\n#define %s\n\n' % (HEADER_GUARD, HEADER_GUARD))

        write_buffer(f,
            '/* Self-signed ECDSA P-256 certificate with an\n'
            ' * x500UniqueIdentifier (OID 2.5.4.45) BIT STRING in both the\n'
            ' * subject and issuer DN. Valid %s to %s, but the tests\n'
            ' * parse with NO_VERIFY so the dates are never checked. */\n'
            % (pretty_date(NOT_BEFORE), pretty_date(NOT_AFTER)),
            'leafUniqueIdDer', make_cert(UNIQUE_ID))

        write_buffer(f,
            '/* Attribute value as stored, with the unused-bits octet\n'
            ' * stripped. */\n',
            'expUniqueId', UNIQUE_ID)

        write_buffer(f,
            '/* Same certificate but with an embedded 0x00 in the value. The\n'
            ' * subject display string truncates at the NUL, but the\n'
            ' * WOLFSSL_X509_NAME entry must carry the full value. */\n',
            'leafEmbeddedNulDer', make_cert(EMBEDDED_NUL_ID))

        f.write('#ifdef OPENSSL_EXTRA\n')
        write_buffer(f, '', 'expEmbeddedNul', EMBEDDED_NUL_ID, False)
        f.write('#endif /* OPENSSL_EXTRA */\n\n')

        f.write('#ifndef WOLFSSL_NO_ASN_STRICT\n')
        write_buffer(f,
            '/* Same certificate but with an empty BIT STRING value, which is\n'
            ' * rejected like a zero length DirectoryString. */\n',
            'leafEmptyUniqueIdDer', make_cert(EMPTY_ID), False)
        f.write('#endif /* !WOLFSSL_NO_ASN_STRICT */\n\n')

        f.write('#endif /* %s */\n' % HEADER_GUARD)
    print('wrote %s' % HEADER_PATH)
