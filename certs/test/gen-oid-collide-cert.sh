#!/bin/sh
#
# Regenerates certs/test/cert-ext-oid-collide.der, whose extension OID maps via
# wc_oid_sum() to a NID with a longer canonical OID. That shrink is what
# test_wolfSSL_X509_set_ext_oid_collision() exercises.
#
# wc_oid_sum() (wolfcrypt/src/asn.c) is an invertible four lane XOR fold, so a
# four byte OID exists for any sum. This one collides with prime256v1:
#
#     2A 86 48 CE 3D 03 01 07  (prime256v1)  -> 0x49498517
#     E8 85 B6 49                            -> 0x49498517
#
# Those bytes are a single subidentifier, which openssl will not emit from a
# dotted OID, hence the DER surgery instead of `openssl req`. The signature is
# left stale; the test parses without verifying.
#
# Run from the wolfssl root directory.

set -e

BASE=certs/ca-ecc-cert.der
OUT=certs/test/cert-ext-oid-collide.der
OID_HEX="E8 85 B6 49"

if [ ! -f "$BASE" ]; then
    echo "Run from the wolfssl root directory (missing $BASE)" >&2
    exit 1
fi

# Re-check the collision in case wc_oid_sum() changed.
python3 - "$OID_HEX" <<'EOF'
import sys

def oid_sum(data):
    oid, shift = 0, 0
    for b in data:
        oid ^= (~b & 0xFFFFFFFF) << shift
        oid &= 0xFFFFFFFF
        shift = (shift + 8) & 0x1f
    return oid & 0x7fffffff

prime256v1 = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
chosen = bytes.fromhex(sys.argv[1].replace(' ', ''))
print("prime256v1 sum = 0x%08X" % oid_sum(prime256v1))
print("chosen     sum = 0x%08X" % oid_sum(chosen))
if oid_sum(prime256v1) != oid_sum(chosen):
    sys.exit("OID no longer collides with prime256v1; pick a new one")
EOF

python3 - "$BASE" "$OUT" "$OID_HEX" <<'EOF'
import sys

src, dst, oid_hex = sys.argv[1], sys.argv[2], sys.argv[3]
oid_content = bytes.fromhex(oid_hex.replace(' ', ''))


def tlv(buf, i=0):
    """(tag, header len, content len, content start) at i."""
    tag = buf[i]
    j = i + 1
    n = buf[j]
    j += 1
    if n & 0x80:
        cnt = n & 0x7F
        n = int.from_bytes(buf[j:j + cnt], 'big')
        j += cnt
    return tag, j - i, n, j


def children(buf):
    """Split constructed content into raw TLV slices."""
    out, i = [], 0
    while i < len(buf):
        _, _, cl, cs = tlv(buf, i)
        out.append(buf[i:cs + cl])
        i = cs + cl
    return out


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def wrap(tag, content):
    return bytes([tag]) + enc_len(len(content)) + content


def content_of(raw):
    _, _, cl, cs = tlv(raw)
    return raw[cs:cs + cl]


cert = open(src, 'rb').read()
tbs, sigalg, sig = children(content_of(cert))

fields = children(content_of(tbs))
# Replace the [3] extensions element with our own.
fields = [f for f in fields if f[0] != 0xA3]

# SEQUENCE { extnID OID, extnValue OCTET STRING }. critical is omitted so the
# parser does not reject an unknown critical extension.
ext = wrap(0x30, wrap(0x06, oid_content) + wrap(0x04, b'\x01\x02\x03\x04'))
fields.append(wrap(0xA3, wrap(0x30, ext)))

out = wrap(0x30, wrap(0x30, b''.join(fields)) + sigalg + sig)
open(dst, 'wb').write(out)
print("Created: %s (%d bytes), extension OID content %s"
      % (dst, len(out), oid_content.hex(' ')))
EOF
