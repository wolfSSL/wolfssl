#!/usr/bin/env python3
"""
    Generates certs/test/cert-events/*.der, the certificates used by the
    certificate validation event tests in tests/api/test_certman.c.

    Each certificate is a copy of certs/server-cert.der (same subject and
    public key) with exactly one defect, signed again with certs/ca-key.pem.
    Signing again matters: verification then reaches the defect instead of
    stopping at a bad signature. good.der has no defect and must verify.

    Defects in an extension are placed inside the extension's OCTET STRING,
    so the certificate as a whole is still valid DER. Defects in other fields
    break the encoding of that field only.

    The validity period runs to 2049, so the certificates do not need to be
    renewed with the other test certificates. The CA must still be the one in
    certs/ca-cert.pem: run this again if that CA's key changes.

    The crl-*.der files are CRLs, each with one fault except crl-good.der.
    crl-revokes-good.der revokes good.der. crl-signer-no-crlsign.der is signed
    by ca-no-crlsign.der, a CA whose keyUsage lacks cRLSign.

    The strict-*.der files test the strict profile checks. strict-good.der
    passes all of them: it has an AKID, a CRL distribution point and an OCSP
    responder. Each other one lacks one of those, or is a CA without a
    keyUsage. crl-this-update-future.der has a thisUpdate in 2049.

    The chain-*.pem files are certificate chains for a TLS server using
    certs/server-key.pem: the server's certificate first, then the CAs it
    sends. Their CAs use the keys in certs/intermediate/ and lead up to
    certs/ca-cert.pem.

    Requires: Python 3 and an openssl command line tool (no Python packages).
    Usage:    python3 ./certs/test/gen-cert-events.py
              (run from the top of the wolfSSL source tree)
"""
import base64
import hashlib
import os
import subprocess
import tempfile

SRC_CERT = './certs/server-cert.der'
CA_CERT = './certs/ca-cert.der'
CA_KEY = './certs/ca-key.pem'
SERVER_KEY = './certs/server-key.pem'
INT_KEY = './certs/intermediate/ca-int-key.pem'
INT2_KEY = './certs/intermediate/ca-int2-key.pem'
OUT_DIR = './certs/test/cert-events'

# UTCTime, YYMMDDHHMMSSZ. 49 maps to 2049 per RFC 5280 4.1.2.5.1.
NOT_BEFORE = '250101000000Z'
NOT_AFTER = '491231235959Z'
FIRST_SERIAL = 0x0CE7E000

OID_SHA256_RSA = '1.2.840.113549.1.1.11'
OID_SKID = '2.5.29.14'
OID_KEY_USAGE = '2.5.29.15'
OID_ALT_NAMES = '2.5.29.17'
OID_BASIC_CA = '2.5.29.19'
OID_CRL_DIST = '2.5.29.31'
OID_CERT_POLICY = '2.5.29.32'
OID_AKID = '2.5.29.35'
OID_EXT_KEY_USAGE = '2.5.29.37'
OID_AUTH_INFO = '1.3.6.1.5.5.7.1.1'
OID_UNKNOWN = '1.3.6.1.4.1.99999.1'
OID_SHA384_RSA = '1.2.840.113549.1.1.12'
OID_COMMON_NAME = '2.5.4.3'
OID_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2'
OID_CRL_NUMBER = '2.5.29.20'
OID_AD_OCSP = '1.3.6.1.5.5.7.48.1'
OID_AD_CA_ISSUERS = '1.3.6.1.5.5.7.48.2'

# Inside an extension value: a SEQUENCE whose first element claims more bytes
# than there are. The outer certificate stays valid DER.
TRUNCATED_INNER = bytes([0x30, 0x03, 0x30, 0x05, 0x00])


def tlv(tag: int, value: bytes) -> bytes:
    """Encode one DER tag, length and value."""
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    else:
        enc = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        length = bytes([0x80 | len(enc)]) + enc
    return bytes([tag]) + length + value


def der_sequence(*items: bytes) -> bytes:
    return tlv(0x30, b''.join(items))


def der_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split('.')]
    body = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        enc = [arc & 0x7f]
        arc >>= 7
        while arc:
            enc.insert(0, 0x80 | (arc & 0x7f))
            arc >>= 7
        body += bytes(enc)
    return tlv(0x06, body)


def der_integer(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 8) // 8, 'big')
    return tlv(0x02, body)


def der_octet_string(value: bytes) -> bytes:
    return tlv(0x04, value)


def read_tlv(data: bytes, idx: int):
    """Return (tag, header length, value length) of the TLV at idx."""
    tag = data[idx]
    n = data[idx + 1]
    if n < 0x80:
        return tag, 2, n
    cnt = n & 0x7f
    return tag, 2 + cnt, int.from_bytes(data[idx + 2:idx + 2 + cnt], 'big')


def children(data: bytes) -> list:
    """Split the value of a constructed TLV into its encoded children."""
    out = []
    idx = 0
    while idx < len(data):
        _, hdr, n = read_tlv(data, idx)
        out.append(data[idx:idx + hdr + n])
        idx += hdr + n
    return out


def value_of(encoded: bytes) -> bytes:
    _, hdr, n = read_tlv(encoded, 0)
    return encoded[hdr:hdr + n]


def extension(oid: str, value: bytes, critical: bool = False) -> bytes:
    crit = tlv(0x01, b'\xff') if critical else b''
    return der_sequence(der_oid(oid), crit, der_octet_string(value))


def load_parts():
    """Subject, issuer and key come from the existing test certificates."""
    with open(SRC_CERT, 'rb') as f:
        tbs = children(value_of(f.read()))[0]
    fields = children(value_of(tbs))
    # version, serial, signature, issuer, validity, subject, spki, ...
    subject, spki = fields[5], fields[6]
    with open(CA_CERT, 'rb') as f:
        ca_tbs = children(value_of(f.read()))[0]
    ca_fields = children(value_of(ca_tbs))
    issuer = ca_fields[5]
    ca_skid = None
    for f_ in ca_fields:
        if f_[0] == 0xa3:
            for ext in children(value_of(children(value_of(f_))[0])):
                parts = children(value_of(ext))
                if parts[0] == der_oid(OID_SKID):
                    ca_skid = value_of(value_of(parts[-1]))
    return subject, spki, issuer, ca_skid


def base_extensions(ca_skid: bytes) -> dict:
    """The extensions of good.der, by name. Each defect replaces one."""
    return {
        'skid': extension(OID_SKID, der_octet_string(bytes(range(1, 21)))),
        'akid': extension(OID_AKID, der_sequence(tlv(0x80, ca_skid))),
        'bc': extension(OID_BASIC_CA, der_sequence(), critical=True),
        # digitalSignature and keyEncipherment
        'ku': extension(OID_KEY_USAGE, tlv(0x03, b'\x05\xa0'), critical=True),
    }


def bad_name(parts):
    """A Name whose RDN holds an INTEGER where a SET is expected."""
    return der_sequence(der_integer(5))


def unknown_key_spki(parts):
    """The real key under an unknown algorithm OID."""
    spki = children(value_of(parts[1]))
    return der_sequence(der_sequence(der_oid(OID_UNKNOWN), tlv(0x05, b'')),
                        spki[1])


def bad_bitstring_spki(parts):
    """A subjectPublicKey BIT STRING claiming 9 unused bits."""
    spki = children(value_of(parts[1]))
    key = value_of(spki[1])
    return der_sequence(spki[0], tlv(0x03, b'\x09' + key[1:]))


# Defects in fields other than extensions: field name -> replacement, or a
# function of the parts read from the existing certificates.
FIELD_CASES = {
    'version-unsupported': ('version is v6, which does not exist',
                            {'version': tlv(0xa0, der_integer(5))}),
    'version-not-integer': ('version is an OCTET STRING',
                            {'version': tlv(0xa0, der_octet_string(b'\x02'))}),
    'serial-empty': ('serialNumber is an INTEGER with no content',
                     {'serial': tlv(0x02, b'')}),
    'serial-not-integer': ('serialNumber is an OCTET STRING',
                           {'serial': der_octet_string(b'\x01\x02')}),
    'tbs-sigalg-unknown': ('signature algorithm in the TBS is unknown',
                           {'tbs_sig_alg': der_sequence(der_oid(OID_UNKNOWN),
                                                        tlv(0x05, b''))}),
    'issuer-malformed': ('issuer Name holds an INTEGER, not a SET',
                         {'issuer': bad_name}),
    'validity-not-time': ('notBefore is an OCTET STRING, not a time',
                          {'validity': der_sequence(
                              der_octet_string(b'250101000000Z'),
                              tlv(0x17, NOT_AFTER.encode()))}),
    'subject-malformed': ('subject Name holds an INTEGER, not a SET',
                          {'subject': bad_name}),
    'spki-unknown-alg': ('public key algorithm is unknown',
                         {'spki': unknown_key_spki}),
    'spki-bad-bitstring': ('public key BIT STRING claims 9 unused bits',
                           {'spki': bad_bitstring_spki}),
    'sigalg-mismatch': ('outer signature algorithm differs from the TBS one',
                        {'outer_sig_alg': der_sequence(
                            der_oid(OID_SHA384_RSA), tlv(0x05, b''))}),
    'signature-not-bitstring': ('signatureValue is an OCTET STRING',
                                {'sig_tag': 0x04}),
    'trailing-data': ('two bytes after the certificate',
                      {'trailing': b'\x00\x00'}),
}

# name: (description, extensions to replace or add, unique IDs to add)
CASES = {
    'good': ('no defect: must verify', {}, b''),
    'ku-malformed': ('keyUsage is an OCTET STRING, not a BIT STRING',
                     {'ku': extension(OID_KEY_USAGE, der_octet_string(b'\xa0'),
                                      critical=True)}, b''),
    'bc-malformed': ('basicConstraints cA is a 2-byte BOOLEAN',
                     {'bc': extension(OID_BASIC_CA,
                                      der_sequence(tlv(0x01, b'\xff\xff')),
                                      critical=True)}, b''),
    'akid-malformed': ('authorityKeyIdentifier is not a SEQUENCE',
                       {'akid': extension(OID_AKID,
                                          der_octet_string(b'\x00\x00'))}, b''),
    'skid-malformed': ('subjectKeyIdentifier is not an OCTET STRING',
                       {'skid': extension(OID_SKID, der_sequence())}, b''),
    'eku-malformed': ('extendedKeyUsage holds an INTEGER, not an OID',
                      {'eku': extension(OID_EXT_KEY_USAGE,
                                        der_sequence(der_integer(1)))}, b''),
    'san-malformed': ('subjectAltName entry claims more bytes than it has',
                      {'san': extension(OID_ALT_NAMES,
                                        bytes([0x30, 0x03, 0x82, 0x05,
                                               0x61]))}, b''),
    'crldp-malformed': ('cRLDistributionPoints is truncated inside',
                        {'crldp': extension(OID_CRL_DIST, TRUNCATED_INNER)},
                        b''),
    'aia-malformed': ('authorityInfoAccess is truncated inside',
                      {'aia': extension(OID_AUTH_INFO, TRUNCATED_INNER)}, b''),
    'policy-malformed': ('certificatePolicies is truncated inside',
                         {'policy': extension(OID_CERT_POLICY,
                                              TRUNCATED_INNER)}, b''),
    'unknown-critical': ('an unknown extension marked critical',
                         {'unknown': extension(OID_UNKNOWN, b'\x05\x00',
                                               critical=True)}, b''),
    'issuer-uid': ('issuerUniqueID present',
                   {}, tlv(0x81, b'\x00\xab\xcd')),
    'subject-uid': ('subjectUniqueID present',
                    {}, tlv(0x82, b'\x00\xab\xcd')),
}


def sign(tbs: bytes, key: str = CA_KEY) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        tbs_file = os.path.join(tmp, 'tbs.der')
        sig_file = os.path.join(tmp, 'sig.bin')
        with open(tbs_file, 'wb') as f:
            f.write(tbs)
        subprocess.run(['openssl', 'dgst', '-sha256', '-sign', key,
                        '-out', sig_file, tbs_file], check=True)
        with open(sig_file, 'rb') as f:
            return f.read()


def public_key(key: str) -> bytes:
    """SubjectPublicKeyInfo of an RSA private key file."""
    out = subprocess.run(['openssl', 'rsa', '-in', key, '-pubout',
                          '-outform', 'DER'], check=True,
                         capture_output=True)
    return out.stdout


def name(common_name: str) -> bytes:
    atv = der_sequence(der_oid(OID_COMMON_NAME),
                       tlv(0x0c, common_name.encode()))
    return der_sequence(tlv(0x31, atv))


def chain_cert(serial: int, subject: bytes, spki: bytes, issuer: bytes,
               issuer_skid: bytes, key: str, ca: bool = False,
               path_len: int = None, key_usage: bytes = None,
               eku: list = None) -> bytes:
    """A certificate for a chain, with the extensions a CA or leaf needs."""
    sig_alg = der_sequence(der_oid(OID_SHA256_RSA), tlv(0x05, b''))
    validity = der_sequence(tlv(0x17, NOT_BEFORE.encode()),
                            tlv(0x17, NOT_AFTER.encode()))
    bc = tlv(0x01, b'\xff') if ca else b''
    if path_len is not None:
        bc += der_integer(path_len)
    if key_usage is None:
        # keyCertSign and cRLSign for a CA; else digitalSignature and
        # keyEncipherment
        key_usage = b'\x01\x06' if ca else b'\x05\xa0'
    exts = [
        extension(OID_SKID, der_octet_string(skid_of(spki))),
        extension(OID_AKID, der_sequence(tlv(0x80, issuer_skid))),
        extension(OID_BASIC_CA, der_sequence(bc), critical=True),
        extension(OID_KEY_USAGE, tlv(0x03, key_usage), critical=True),
    ]
    if eku is not None:
        exts.append(extension(OID_EXT_KEY_USAGE,
                              der_sequence(*[der_oid(o) for o in eku])))
    tbs = der_sequence(tlv(0xa0, der_integer(2)), der_integer(serial),
                       sig_alg, issuer, validity, subject, spki,
                       tlv(0xa3, der_sequence(*exts)))
    return der_sequence(tbs, sig_alg, tlv(0x03, b'\x00' + sign(tbs, key)))


def skid_of(spki: bytes) -> bytes:
    return hashlib.sha1(spki).digest()


def pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ('-----BEGIN CERTIFICATE-----\n' + '\n'.join(lines) +
            '\n-----END CERTIFICATE-----\n')


def build_chains(parts, serial: int):
    """Chains for a TLS server, and leaves that fail against their signer."""
    subject, spki, root, root_skid = parts
    int_spki = public_key(INT_KEY)
    int2_spki = public_key(INT2_KEY)
    out = {}

    def next_serial():
        nonlocal serial
        serial += 1
        return serial

    def ca_under_root(cn, **kw):
        return chain_cert(next_serial(), name(cn), int_spki, root,
                          root_skid, CA_KEY, **kw)

    def leaf_under(cn, **kw):
        return chain_cert(next_serial(), subject, spki, name(cn),
                          skid_of(int_spki), INT_KEY, **kw)

    # Good: server, then a CA signed by the root.
    cn = 'Cert Events Int CA'
    out['chain-good'] = ('a good chain',
                         [leaf_under(cn), ca_under_root(cn, ca=True)])
    # The server's signer is not a CA.
    cn = 'Cert Events Int Not CA'
    out['chain-signer-not-ca'] = ('the signer is not a CA',
                                  [leaf_under(cn), ca_under_root(cn)])
    # The signer is a CA that may not sign certificates.
    cn = 'Cert Events Int No Cert Sign'
    out['chain-signer-no-certsign'] = (
        'the signer has keyUsage without keyCertSign',
        [leaf_under(cn), ca_under_root(cn, ca=True, key_usage=b'\x07\x80')])
    # A CA with pathLenConstraint 0 signs another CA.
    cn = 'Cert Events Int Path Len 0'
    cn2 = 'Cert Events Int Below Path Len 0'
    int2 = chain_cert(next_serial(), name(cn2), int2_spki, name(cn),
                      skid_of(int_spki), INT_KEY, ca=True)
    leaf = chain_cert(next_serial(), subject, spki, name(cn2),
                      skid_of(int2_spki), INT2_KEY)
    out['chain-pathlen-exceeded'] = (
        'a CA with pathLenConstraint 0 signs another CA',
        [leaf, int2, ca_under_root(cn, ca=True, path_len=0)])

    singles = {
        # Claims the root as issuer, but signed with another key.
        'leaf-bad-signature': ('signed with a key other than the issuer\'s',
                               chain_cert(next_serial(), subject, spki, root,
                                          root_skid, SERVER_KEY)),
        'leaf-unknown-issuer': ('issued by a CA nobody trusts',
                                chain_cert(next_serial(), subject, spki,
                                           name('Cert Events Unknown CA'),
                                           bytes(20), CA_KEY)),
    }

    # Added later, so the serials above stay the same. The server's own
    # certificate may not be used for this TLS connection.
    cn = 'Cert Events Int CA'
    out['chain-leaf-ku-no-digsig'] = (
        'the server\'s keyUsage has keyEncipherment only',
        [leaf_under(cn, key_usage=b'\x05\x20'), ca_under_root(cn, ca=True)])
    out['chain-leaf-eku-client-only'] = (
        'the server\'s extendedKeyUsage allows clientAuth only',
        [leaf_under(cn, eku=[OID_CLIENT_AUTH]), ca_under_root(cn, ca=True)])

    return out, singles


def build(serial: int, exts: dict, uids: bytes, parts,
          fields: dict = None) -> bytes:
    subject, spki, issuer, _ = parts
    sig_alg = der_sequence(der_oid(OID_SHA256_RSA), tlv(0x05, b''))
    f = {
        'version': tlv(0xa0, der_integer(2)),
        'serial': der_integer(serial),
        'tbs_sig_alg': sig_alg,
        'issuer': issuer,
        'validity': der_sequence(tlv(0x17, NOT_BEFORE.encode()),
                                 tlv(0x17, NOT_AFTER.encode())),
        'subject': subject,
        'spki': spki,
        'outer_sig_alg': sig_alg,
        'sig_tag': 0x03,
        'trailing': b'',
    }
    for name, value in (fields or {}).items():
        f[name] = value(parts) if callable(value) else value
    ext_block = tlv(0xa3, der_sequence(*exts.values()))
    tbs = der_sequence(f['version'], f['serial'], f['tbs_sig_alg'],
                       f['issuer'], f['validity'], f['subject'], f['spki'],
                       uids, ext_block)
    signature = tlv(f['sig_tag'], b'\x00' + sign(tbs))
    return der_sequence(tbs, f['outer_sig_alg'], signature) + f['trailing']


def build_crl(issuer: bytes, issuer_skid: bytes, key: str, revoked: list,
              next_update: str = NOT_AFTER, extra: bytes = b'',
              entry_serial: bytes = None,
              this_update: str = NOT_BEFORE) -> bytes:
    """A version 2 CRL with an AKID and a CRL number."""
    sig_alg = der_sequence(der_oid(OID_SHA256_RSA), tlv(0x05, b''))
    entries = [der_sequence(entry_serial or der_integer(sn),
                            tlv(0x17, NOT_BEFORE.encode()))
               for sn in revoked]
    exts = [
        extension(OID_AKID, der_sequence(tlv(0x80, issuer_skid))),
        extension(OID_CRL_NUMBER, der_integer(1)),
    ]
    tbs = der_sequence(der_integer(1), sig_alg, issuer,
                       tlv(0x17, this_update.encode()),
                       tlv(0x17, next_update.encode()),
                       der_sequence(*entries) if entries else b'',
                       tlv(0xa0, der_sequence(*exts, extra)))
    return der_sequence(tbs, sig_alg, tlv(0x03, b'\x00' + sign(tbs, key)))


def build_crls(parts, serial: int):
    """CRLs issued by certs/ca-cert.pem, and a CA that may not sign CRLs."""
    _, _, root, root_skid = parts
    int_spki = public_key(INT_KEY)
    good_serial = FIRST_SERIAL  # good.der
    out = {
        'crl-good': ('a good CRL that revokes nothing',
                     build_crl(root, root_skid, CA_KEY, [])),
        'crl-revokes-good': ('revokes good.der',
                             build_crl(root, root_skid, CA_KEY,
                                       [good_serial])),
        'crl-expired': ('nextUpdate is in 2025',
                        build_crl(root, root_skid, CA_KEY, [],
                                  next_update='250601000000Z')),
        'crl-bad-signature': ('signed with a key other than the issuer\'s',
                              build_crl(root, root_skid, SERVER_KEY, [])),
        'crl-unknown-issuer': ('issued by a CA nobody trusts',
                               build_crl(name('Cert Events Unknown CA'),
                                         bytes(20), CA_KEY, [])),
        'crl-malformed': ('a revoked entry\'s serial is an OCTET STRING',
                          build_crl(root, root_skid, CA_KEY, [1],
                                    entry_serial=der_octet_string(b'\x01'))),
        'crl-unknown-critical': ('an unknown CRL extension marked critical',
                                 build_crl(root, root_skid, CA_KEY, [],
                                           extra=extension(OID_UNKNOWN,
                                               b'\x05\x00',
                                               critical=True))),
    }
    # A CA whose keyUsage has keyCertSign but not cRLSign, and a CRL it
    # signed.
    cn = 'Cert Events Int No CRL Sign'
    out['ca-no-crlsign'] = (
        'a CA that may not sign CRLs',
        chain_cert(serial, name(cn), int_spki, root, root_skid, CA_KEY,
                   ca=True, key_usage=b'\x02\x04'))
    out['crl-signer-no-crlsign'] = (
        'signed by ca-no-crlsign.der',
        build_crl(name(cn), skid_of(int_spki), INT_KEY, []))
    return out


def crl_dp(uri: str) -> bytes:
    """cRLDistributionPoints with one fullName URI."""
    return extension(OID_CRL_DIST, der_sequence(der_sequence(
        tlv(0xa0, tlv(0xa0, tlv(0x86, uri.encode()))))))


def aia(*access: tuple) -> bytes:
    """authorityInfoAccess with (method OID, URI) pairs."""
    return extension(OID_AUTH_INFO, der_sequence(
        *[der_sequence(der_oid(m), tlv(0x86, u.encode()))
          for m, u in access]))


def build_strict(parts, serial: int):
    """Certificates and a CRL for the strict profile checks."""
    _, _, root, root_skid = parts
    full = base_extensions(root_skid)
    full['crldp'] = crl_dp('http://crl.example.com/ca.crl')
    full['aia'] = aia((OID_AD_OCSP, 'http://ocsp.example.com'))
    no_ocsp = dict(full)
    no_ocsp['aia'] = aia((OID_AD_CA_ISSUERS, 'http://ca.example.com/ca.der'))
    ca_no_ku = dict(full)
    del ca_no_ku['ku']
    ca_no_ku['bc'] = extension(OID_BASIC_CA,
                               der_sequence(tlv(0x01, b'\xff')),
                               critical=True)
    cases = [
        ('strict-good', 'passes every strict check', full),
        ('strict-no-akid', 'no authorityKeyIdentifier',
         {k: v for k, v in full.items() if k != 'akid'}),
        ('strict-no-crldp', 'no cRLDistributionPoints',
         {k: v for k, v in full.items() if k != 'crldp'}),
        ('strict-no-ocsp', 'authorityInfoAccess without an OCSP responder',
         no_ocsp),
        ('strict-ca-no-ku', 'a CA without keyUsage', ca_no_ku),
    ]
    out = {}
    for i, (name_, desc, exts) in enumerate(cases):
        out[name_] = (desc, build(serial + i, exts, b'', parts))
    out['crl-this-update-future'] = (
        'thisUpdate is in 2049',
        build_crl(root, root_skid, CA_KEY, [], this_update='490101000000Z'))
    return out


def main():
    parts = load_parts()
    if parts[3] is None:
        raise SystemExit('CA certificate has no subjectKeyIdentifier')
    os.makedirs(OUT_DIR, exist_ok=True)
    jobs = [(name, desc, changes, uids, None)
            for name, (desc, changes, uids) in CASES.items()]
    jobs += [(name, desc, {}, b'', fields)
             for name, (desc, fields) in FIELD_CASES.items()]
    for i, (name, desc, changes, uids, fields) in enumerate(jobs):
        exts = base_extensions(parts[3])
        exts.update(changes)
        der = build(FIRST_SERIAL + i, exts, uids, parts, fields)
        path = os.path.join(OUT_DIR, name + '.der')
        with open(path, 'wb') as f:
            f.write(der)
        print('Created: %s (%s)' % (path, desc))

    chains, singles = build_chains(parts, FIRST_SERIAL + 0x100)
    for name_, (desc, certs) in chains.items():
        path = os.path.join(OUT_DIR, name_ + '.pem')
        with open(path, 'w') as f:
            f.write(''.join(pem(c) for c in certs))
        print('Created: %s (%s)' % (path, desc))
    for name_, (desc, der) in singles.items():
        path = os.path.join(OUT_DIR, name_ + '.der')
        with open(path, 'wb') as f:
            f.write(der)
        print('Created: %s (%s)' % (path, desc))

    for name_, (desc, der) in build_crls(parts,
                                          FIRST_SERIAL + 0x200).items():
        path = os.path.join(OUT_DIR, name_ + '.der')
        with open(path, 'wb') as f:
            f.write(der)
        print('Created: %s (%s)' % (path, desc))

    for name_, (desc, der) in build_strict(parts,
                                            FIRST_SERIAL + 0x300).items():
        path = os.path.join(OUT_DIR, name_ + '.der')
        with open(path, 'wb') as f:
            f.write(der)
        print('Created: %s (%s)' % (path, desc))


if __name__ == '__main__':
    main()
