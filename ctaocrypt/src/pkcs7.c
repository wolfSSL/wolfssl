/* pkcs7.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#ifdef HAVE_PKCS7

#include <cyassl/ctaocrypt/pkcs7.h>
#include <cyassl/ctaocrypt/error.h>
#include <cyassl/ctaocrypt/logging.h>

CYASSL_LOCAL int SetContentType(int pkcs7TypeOID, byte* output)
{
    /* PKCS#7 content types */
    static const byte pkcs7[]              = { 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                               0x0D, 0x01, 0x07 };
    static const byte data[]               = { 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                               0x0D, 0x01, 0x07, 0x01 };
    static const byte signedData[]         = { 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                               0x0D, 0x01, 0x07, 0x02};
    static const byte envelopedData[]      = { 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                               0x0D, 0x01, 0x07, 0x03 };
    static const byte signedAndEnveloped[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                               0x0D, 0x01, 0x07, 0x04 };
    static const byte digestedData[]       = { 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                               0x0D, 0x01, 0x07, 0x05 };
    static const byte encryptedData[]      = { 0x2A, 0x86, 0x48, 0x86, 0xF7,
                                               0x0D, 0x01, 0x07, 0x06 };

    int idSz;
    int typeSz = 0, idx = 0;
    const byte* typeName = 0;
    byte ID_Length[MAX_LENGTH_SZ];

    switch (pkcs7TypeOID) {
        case PKCS7_MSG:
            typeSz = sizeof(pkcs7);
            typeName = pkcs7;
            break;

        case DATA:
            typeSz = sizeof(data);
            typeName = data;
            break;

        case SIGNED_DATA:
            typeSz = sizeof(signedData);
            typeName = signedData;
            break;
        
        case ENVELOPED_DATA:
            typeSz = sizeof(envelopedData);
            typeName = envelopedData;
            break;

        case SIGNED_AND_ENVELOPED_DATA:
            typeSz = sizeof(signedAndEnveloped);
            typeName = signedAndEnveloped;
            break;

        case DIGESTED_DATA:
            typeSz = sizeof(digestedData);
            typeName = digestedData;
            break;

        case ENCRYPTED_DATA:
            typeSz = sizeof(encryptedData);
            typeName = encryptedData;
            break;

        default:
            CYASSL_MSG("Unknown PKCS#7 Type");
            return 0;
    };

    idSz  = SetLength(typeSz, ID_Length);
    output[idx++] = ASN_OBJECT_ID;
    XMEMCPY(output + idx, ID_Length, idSz);
    idx += idSz;
    XMEMCPY(output + idx, typeName, typeSz);
    idx += typeSz;

    return idx;

}

/* Create PKCS#7 envelopedData structure */
int Pkcs7_encrypt(const byte* certs, word32 certSz, byte* data, word32 dataSz,
                  int cipher, byte* out, word32* outSz, word32 flags)
{
    (void)certs;
    (void)certSz;
    (void)data;
    (void)dataSz;
    (void)cipher;
    (void)out;
    (void)outSz;
    (void)flags;

    return 0;
}


int PKCS7_InitWithCert(PKCS7* pkcs7, byte* cert, word32 certSz)
{
    XMEMSET(pkcs7, 0, sizeof(PKCS7));
    pkcs7->singleCert = cert;
    pkcs7->singleCertSz = certSz;

    return 0;
}


int PKCS7_EncodeData(PKCS7* pkcs7, byte* output, word32 outputSz)
{
    static const byte oid[] =
        { ASN_OBJECT_ID, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
                         0x07, 0x01 };
    byte seq[MAX_SEQ_SZ];
    byte octetStr[MAX_OCTET_STR_SZ];
    word32 seqSz;
    word32 octetStrSz;
    int idx = 0;

    octetStrSz = SetOctetString(pkcs7->contentSz, octetStr);
    seqSz = SetSequence(pkcs7->contentSz + octetStrSz + sizeof(oid), seq);

    if (outputSz < pkcs7->contentSz + octetStrSz + sizeof(oid) + seqSz)
        return BUFFER_E;

    XMEMCPY(output, seq, seqSz);
    idx += seqSz;
    XMEMCPY(output + idx, oid, sizeof(oid));
    idx += sizeof(oid);
    XMEMCPY(output + idx, octetStr, octetStrSz);
    idx += octetStrSz;
    XMEMCPY(output + idx, pkcs7->content, pkcs7->contentSz);
    idx += pkcs7->contentSz;

    return idx;
}


int PKCS7_EncodeSignedData(PKCS7* pkcs7, byte* output, word32 outputSz)
{
    (void)pkcs7;
    (void)output;
    (void)outputSz;
    return 0;
}


int PKCS7_EncodeEnvelopeData(PKCS7* pkcs7, byte* output, word32 outputSz)
{
    (void)pkcs7;
    (void)output;
    (void)outputSz;
    return 0;
}


#else  /* HAVE_PKCS7 */


#ifdef _MSC_VER
    /* 4206 warning for blank file */
    #pragma warning(disable: 4206)
#endif


#endif /* HAVE_PKCS7 */

