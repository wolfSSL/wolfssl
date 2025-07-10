#!/usr/bin/env python3
"""
    This is a simple generator of OCSP responses that will be used to test
    wolfSSL OCSP implementation
"""
from pyasn1_modules import rfc6960
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
from pyasn1.type import univ, tag, useful, namedtype
from base64 import b64decode
from hashlib import sha1, sha256
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend

WOLFSSL_OCSP_CERT_PATH = './certs/ocsp/'

def response_status(value: int) -> rfc6960.OCSPResponseStatus:
    return rfc6960.OCSPResponseStatus(value)

def response_type() -> univ.ObjectIdentifier:
    return rfc6960.id_pkix_ocsp_basic

sha256WithRSAEncryption = (1, 2, 840, 113549, 1, 1, 11)
sha1_alg_id = (1, 3, 14, 3, 2, 26)
def cert_id_sha1_alg_id() -> rfc6960.AlgorithmIdentifier:
    return algorithm(sha1_alg_id)

def signature_algorithm() -> rfc6960.AlgorithmIdentifier:
    return algorithm(sha256WithRSAEncryption)

def algorithm(value) -> rfc6960.AlgorithmIdentifier:
    ai = rfc6960.AlgorithmIdentifier()
    ai['algorithm'] = univ.ObjectIdentifier(value=value)
    return ai

def cert_pem_to_der(cert_path: str) -> bytes:
    beg_cert = '-----BEGIN CERTIFICATE-----'
    end_cert = '-----END CERTIFICATE-----'
    with open(cert_path, 'r') as f:
        pem = f.read()
    cert = pem.split(beg_cert)[1].split(end_cert)[0]
    return b64decode(cert)

def certs(cert_path: list[str]) -> univ.SequenceOf | None:
    if len(cert_path) == 0:
        return None
    certs = rfc6960.BasicOCSPResponse()['certs']
    for cp in cert_path:
        cert_der = cert_pem_to_der(cp)
        cert, _ = decode(bytes(cert_der), asn1Spec=rfc6960.Certificate())
        certs.append(cert)
    return certs

def signature(bitstr: str) -> univ.BitString:
    return univ.BitString(hexValue=bitstr)

def resp_id_by_name(cert_path: str) -> rfc6960.ResponderID:
    cert_der = cert_pem_to_der(cert_path)
    cert, _ = decode(bytes(cert_der), asn1Spec=rfc6960.Certificate())
    subj = cert['tbsCertificate']['subject']
    rid = rfc6960.ResponderID()
    rdi_name = rid['byName']
    rdi_name['rdnSequence'] = subj['rdnSequence']
    return rid

def resp_id_by_key(cert_path: str) -> rfc6960.ResponderID:
    cert_der = cert_pem_to_der(cert_path)
    cert, _ = decode(bytes(cert_der), asn1Spec=rfc6960.Certificate())
    key = get_key(cert)
    key_hash = sha1(key.asOctets()).digest()
    rid = rfc6960.ResponderID()
    rid['byKey'] = rfc6960.KeyHash(value=key_hash).subtype(explicitTag=
                                                           tag.Tag(
                                                           tag.tagClassContext,
                                                           tag.tagFormatSimple,
                                                           2))
    return rid

def get_key(cert: rfc6960.Certificate) -> univ.BitString:
    return cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']

def get_name(cert: rfc6960.Certificate) -> rfc6960.Name:
    return cert['tbsCertificate']['subject']

def cert_id_from_hash(issuer_name_hash: bytes, issuer_key_hash: bytes,
                      serial: int) -> rfc6960.CertID:
    cert_id = rfc6960.CertID()
    cert_id['hashAlgorithm'] = cert_id_sha1_alg_id()
    cert_id['issuerNameHash'] = univ.OctetString(value=issuer_name_hash)
    cert_id['issuerKeyHash'] = univ.OctetString(value=issuer_key_hash)
    cert_id['serialNumber'] = rfc6960.CertificateSerialNumber(serial)
    return cert_id

def cert_id(issuer_cert_path: str, serial: int) -> rfc6960.CertID:
    issuer_cert = cert_pem_to_der(issuer_cert_path)
    issuer, _ = decode(bytes(issuer_cert), asn1Spec=rfc6960.Certificate())
    issuer_name = get_name(issuer)
    issuer_key = get_key(issuer)
    issuer_name_hash = sha1(encode(issuer_name)).digest()
    issuer_key_hash = sha1(issuer_key.asOctets()).digest()
    cert_id = rfc6960.CertID()
    cert_id['hashAlgorithm'] = cert_id_sha1_alg_id()
    cert_id['issuerNameHash'] = univ.OctetString(value=issuer_name_hash)
    cert_id['issuerKeyHash'] = univ.OctetString(value=issuer_key_hash)
    cert_id['serialNumber'] = rfc6960.CertificateSerialNumber(serial)

    return cert_id

CERT_GOOD = 0
CERT_REVOKED = 1
CERT_UNKNOWN = 2
def cert_status(value: int) -> rfc6960.CertStatus:
    cs = rfc6960.CertStatus()

    if value == CERT_GOOD:
        good = univ.Null('').subtype(implicitTag=tag.Tag(tag.tagClassContext,
                                                         tag.tagFormatSimple,
                                                         0))
        cs['good'] = good
    elif value == CERT_REVOKED:
        revoked = rfc6960.RevokedInfo().subtype(implicitTag=tag.Tag(
            tag.tagClassContext, tag.tagFormatSimple, 1))
        revoked['revocationTime'] = useful.GeneralizedTime().fromDateTime(
            datetime.now())
        cs['revoked'] = revoked

    return cs

def single_response(issuer_cert_path: str, serial: int,
                    status: int) -> rfc6960.SingleResponse:
    cid = cert_id(issuer_cert_path, serial)
    cs = cert_status(status)
    sr = rfc6960.SingleResponse().clone()
    sr.setComponentByName('certID', cid)
    sr['certStatus'] = cs
    sr['thisUpdate'] = useful.GeneralizedTime().fromDateTime(datetime.now())
    return sr

def response_data(rid: rfc6960.ResponderID | None,
                  responses: list[rfc6960.SingleResponse]) -> rfc6960.ResponseData:
    rd = rfc6960.ResponseData()
    rd['version'] = rfc6960.Version('v1').subtype(explicitTag=tag.Tag(
        tag.tagClassContext, tag.tagFormatSimple, 0))
    if rid:
        rd['responderID'] = rid
    rd['producedAt'] = useful.GeneralizedTime().fromDateTime(datetime.now())
    rs = univ.SequenceOf(componentType=rfc6960.SingleResponse())
    rs.extend(responses)
    rd['responses'] = rs
    return rd

def read_key_der_from_pem(key_path: str) -> bytes:
    with open(key_path, 'r') as f:
        pem = f.readlines()
    pem_start = [i for i, line in enumerate(pem) if '-----BEGIN' in line][0]
    pem_end = [i for i, line in enumerate(pem) if '-----END' in line][0]
    key = ''.join(pem[pem_start+1:pem_end])
    return b64decode(key)

def basic_ocsp_response(rd: rfc6960.ResponseData, sig_alg:
                        rfc6960.AlgorithmIdentifier, sig: univ.BitString,
                        certs: univ.SequenceOf|None = None) -> rfc6960.BasicOCSPResponse:
    br = rfc6960.BasicOCSPResponse()

    br['tbsResponseData'] = rd
    br['signatureAlgorithm'] = sig_alg
    br['signature'] = sig
    if certs is not None:
        br['certs'] = certs
    return br

def response_bytes(br: rfc6960.BasicOCSPResponse) -> rfc6960.ResponseBytes:
    rb = rfc6960.ResponseBytes().subtype(explicitTag=tag.Tag(
        tag.tagClassContext, tag.tagFormatConstructed, 0))
    rb['responseType'] = response_type()
    rb['response'] = encode(br)
    return rb

def ocsp_response(status: rfc6960.OCSPResponseStatus,
                  response_bytes: rfc6960.ResponseBytes) -> rfc6960.OCSPResponse:
    orsp = rfc6960.OCSPResponse()
    orsp['responseStatus'] = status
    orsp['responseBytes'] = response_bytes
    return orsp

def get_priv_key(pem_path) -> rsa.RSAPrivateKey:
    key_der = read_key_der_from_pem(pem_path)
    private_key = serialization.load_der_private_key(
        key_der,
        password=None,
    )
    return private_key

def sign_repsonse_data(rd: rfc6960.ResponseData,
                       key: rsa.RSAPrivateKey) -> univ.BitString:
    sig = key.sign(encode(rd), padding.PKCS1v15(), hashes.SHA256())
    return univ.BitString(hexValue=sig.hex())

def get_pub_key(cert_path: str) -> rsa.RSAPublicKey:
    with open(cert_path, 'rb') as f:
        cert = f.read()
    cert = x509.load_pem_x509_certificate(cert, default_backend())
    return cert.public_key()

def test_signature(ocsp_resp_path: str, key: rsa.RSAPublicKey):
    with open(ocsp_resp_path, 'rb') as f:
        ocsp_resp = f.read()
    ocsp_resp, _ = decode(ocsp_resp, asn1Spec=rfc6960.OCSPResponse())
    response = ocsp_resp.getComponentByName(
        'responseBytes').getComponentByName('response')
    br, _ = decode(response, asn1Spec=rfc6960.BasicOCSPResponse())
    rd = br.getComponentByName('tbsResponseData')
    rd_hash = sha256(encode(rd)).digest()
    di = rfc8017.DigestInfo()
    di['digestAlgorithm'] = signature_algorithm()
    di['digest'] = univ.OctetString(rd_hash)
    sig = br.getComponentByName('signature')
    key.verify(sig.asOctets(), encode(rd), padding.PKCS1v15(), hashes.SHA256())

def single_response_from_cert(cert_path: str,
                              status: int) -> rfc6960.SingleResponse:
    cert_der = cert_pem_to_der(cert_path)
    cert, _ = decode(bytes(cert_der), asn1Spec=rfc6960.Certificate())
    serial = cert['tbsCertificate']['serialNumber']
    issuer = cert['tbsCertificate']['issuer']
    serialHash = sha1(serial.asOctets()).digest()
    issuerHash = sha1(encode(issuer)).digest()
    cid = cert_id_from_hash(issuerHash, serialHash, serial)
    cs = cert_status(status)
    sr = rfc6960.SingleResponse().clone()
    sr.setComponentByName('certID', cid)
    sr['certStatus'] = cs
    sr['thisUpdate'] = useful.GeneralizedTime().fromDateTime(datetime.now())
    return sr

RESPONSE_STATUS_GOOD = 0

def write_buffer(name: str, data: bytes, f):
    f.write(f"unsigned char {name}[] = {{\n")
    for i in range(0, len(data), 12):
        f.write("    " + ", ".join(f"0x{b:02x}" for b in data[i:i+12]) + ",\n")
    f.write("};\n\n")

def create_response(rd: dict) -> rfc6960.OCSPResponse:
    """create a response using definition in rd"""
    cs = response_status(rd.get('response_status', RESPONSE_STATUS_GOOD))
    sa = rd.get('signature_algorithm', signature_algorithm())
    c = certs(rd.get('certs_path', []))
    rid = None
    if rd.get('responder_by_name') is not None:
        rid = resp_id_by_name(
            rd.get(
                'responder_cert', WOLFSSL_OCSP_CERT_PATH + 'ocsp-responder-cert.pem'))
    elif rd.get('responder_by_key', None) is not None:
        rid = resp_id_by_key(
            rd.get('responder_cert', WOLFSSL_OCSP_CERT_PATH + 'ocsp-responder-cert.pem'))
    # implement responder byhash
    responses = []
    for entry in rd.get('responses', []):
        if entry.get('certificate'):
            sr = single_response_from_cert(entry['certificate'], entry['status'])
        else:
            sr = single_response(entry['issuer_cert'], entry['serial'], entry['status'])
        responses.append(sr)
    rd_data = response_data(rid, responses)
    k = get_priv_key(rd.get('responder_key', WOLFSSL_OCSP_CERT_PATH + 'ocsp-responder-key.pem'))
    s = sign_repsonse_data(rd_data, k)
    br = basic_ocsp_response(rd_data, sa, s, c)
    rb = response_bytes(br)
    ocspr = ocsp_response(cs, rb)
    return ocspr

def create_and_write_response(rd: dict, f):
    ocspr = create_response(rd)
    encoded_response = encode(ocspr)
    write_buffer(rd['name'].replace('-', '_').replace('.', '_'), encoded_response, f)

def add_certificate(cert_path: str, f):
    cert_der = cert_pem_to_der(cert_path)
    write_buffer(cert_path.split('/')[-1].replace('-', '_').replace('.', '_'), cert_der, f)

class badOCSPResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('responseBytes', rfc6960.ResponseBytes().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
    )

def create_bad_response(rd: dict) -> bytes:
    """Creates a malformed OCSP response by removing the response status field"""
    r = create_response(rd)
    br = badOCSPResponse()
    br['responseBytes'] = r['responseBytes']
    return encode(br)

if __name__ == '__main__':
    useful.GeneralizedTime._hasSubsecond = False
    response_definitions = [
        {
            'response_status': 0,
            'signature_algorithm': signature_algorithm(),
            'certs_path': [WOLFSSL_OCSP_CERT_PATH + 'ocsp-responder-cert.pem'],
            'responder_by_name': True,
            'responses': [
                {
                    'issuer_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
                    'serial': 0x01,
                    'status': CERT_GOOD
                }
            ],
            'responder_key': WOLFSSL_OCSP_CERT_PATH + 'ocsp-responder-key.pem',
            'name': 'resp'
        },
        {
            'response_status': 0,
            'signature_algorithm': signature_algorithm(),
            'certs_path': [WOLFSSL_OCSP_CERT_PATH + 'ocsp-responder-cert.pem'],
            'responder_by_key': True,
            'responses': [
                {
                    'issuer_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
                    'serial': 0x01,
                    'status': CERT_GOOD
                }
            ],
            'responder_key': WOLFSSL_OCSP_CERT_PATH + 'ocsp-responder-key.pem',
            'name': 'resp_rid_bykey',
        },
        {
            'response_status': 0,
            'signature_algorithm': signature_algorithm(),
            'responder_by_name': True,
            'responses': [
                {
                    'issuer_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
                    'serial': 0x01,
                    'status': CERT_GOOD
                }
            ],
            'responder_key': WOLFSSL_OCSP_CERT_PATH + 'ocsp-responder-key.pem',
            'name': 'resp_nocert'
        },
        {
            'response_status': 0,
            'signature_algorithm': signature_algorithm(),
            'responder_by_name': True,
            'responses': [
                {
                    'issuer_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
                    'serial': 0x01,
                    'status': CERT_GOOD
                },
                {
                    'issuer_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
                    'serial': 0x02,
                    'status': CERT_GOOD
                }
            ],
            'responder_key': WOLFSSL_OCSP_CERT_PATH + 'root-ca-key.pem',
            'responder_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
            'name': 'resp_multi'
        },
        {
            'response_status': 0,
            'signature_algorithm': signature_algorithm(),
            'responder_by_name': True,
            'responses': [
                {
                    'issuer_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
                    'serial': 0x01,
                    'status': CERT_GOOD
                },
                {
                    'issuer_cert': WOLFSSL_OCSP_CERT_PATH + '../ca-cert.pem',
                    'serial': 0x01,
                    'status': CERT_GOOD
                }
            ],
            'responder_key': WOLFSSL_OCSP_CERT_PATH + 'root-ca-key.pem',
            'responder_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
            'name': 'resp_bad_noauth'
        },
        {
            'response_status': 0,
            'signature_algorithm': signature_algorithm(),
            'responder_by_name': True,
            'responses': [
                {
                    'issuer_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
                    'serial': 0x01,
                    'status': CERT_GOOD
                },
            ],
            # unrelated cert
            'certs_path' : [WOLFSSL_OCSP_CERT_PATH + 'intermediate2-ca-cert.pem'],
            'responder_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
            'responder_key': WOLFSSL_OCSP_CERT_PATH + 'root-ca-key.pem',
            'name': 'resp_bad_embedded_cert'
        },
    ]

    with open('./tests/api/test_ocsp_test_blobs.h', 'w') as f:
        f.write(
"""/*
* This file is generated automatically by running ./tests/api/create_ocsp_test_blobs.py.
*
* ocsp_test_blobs.h
*
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
""")
        f.write("#ifndef OCSP_TEST_BLOBS_H\n")
        f.write("#define OCSP_TEST_BLOBS_H\n\n")
        for rd in response_definitions:
            create_and_write_response(rd, f)
        add_certificate(WOLFSSL_OCSP_CERT_PATH + 'ocsp-responder-cert.pem', f)
        add_certificate(WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem', f)
        add_certificate(WOLFSSL_OCSP_CERT_PATH + '../ca-cert.pem', f)
        add_certificate(WOLFSSL_OCSP_CERT_PATH + '../server-cert.pem', f)
        add_certificate(WOLFSSL_OCSP_CERT_PATH + 'intermediate1-ca-cert.pem', f)
        br = create_bad_response({
            'response_status': 0,
            'responder_by_key': True,
            'responses': [
                {
                    'issuer_cert': WOLFSSL_OCSP_CERT_PATH + 'root-ca-cert.pem',
                    'serial': 0x01,
                    'status': CERT_GOOD
                }
            ],
            'name': 'resp_bad'
        })
        write_buffer('resp_bad', br, f)
        f.write("#endif /* OCSP_TEST_BLOBS_H */\n")
