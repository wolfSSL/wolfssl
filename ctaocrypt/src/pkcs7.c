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


/* create ASN.1 fomatted RecipientInfo structure, returns sequence size */
CYASSL_LOCAL int CreateRecipientInfo(const byte* cert, word32 certSz,
                                     int keyEncAlgo, int blockKeySz,
                                     RNG* rng, byte* contentKeyPlain,
                                     byte* contentKeyEnc,
                                     int* keyEncSz, byte* out, word32 outSz)
{
    word32 idx = 0;
    int ret = 0, totalSz = 0;
    int verSz, issuerSz, snSz, keyEncAlgSz;
    int issuerSeqSz, recipSeqSz, issuerSerialSeqSz;
    int encKeyOctetStrSz;

    byte ver[MAX_VERSION_SZ];
    byte serial[MAX_SN_SZ];
    byte issuerSerialSeq[MAX_SEQ_SZ];
    byte recipSeq[MAX_SEQ_SZ];
    byte issuerSeq[MAX_SEQ_SZ];
    byte keyAlgArray[MAX_ALGO_SZ];
    byte encKeyOctetStr[MAX_OCTET_STR_SZ];

    RsaKey pubKey;
    DecodedCert decoded;

    InitDecodedCert(&decoded, (byte*)cert, certSz, 0);
    ret = ParseCert(&decoded, CA_TYPE, NO_VERIFY, 0);
    if (ret < 0) {
        FreeDecodedCert(&decoded);
        return ret;
    }

    /* version */
    verSz = SetMyVersion(0, ver, 0);

    /* IssuerAndSerialNumber */
    if (decoded.issuerRaw == NULL || decoded.issuerRawLen == 0) {
        CYASSL_MSG("DecodedCert lacks raw issuer pointer and length");
        FreeDecodedCert(&decoded);
        return -1;
    }
    issuerSz    = decoded.issuerRawLen;
    issuerSeqSz = SetSequence(issuerSz, issuerSeq);

    if (decoded.serial == NULL || decoded.serialSz == 0) {
        CYASSL_MSG("DecodedCert missing serial number");
        FreeDecodedCert(&decoded);
        return -1;
    }
    snSz = SetSerialNumber(decoded.serial, decoded.serialSz, serial);

    issuerSerialSeqSz = SetSequence(issuerSeqSz + issuerSz + snSz,
                                    issuerSerialSeq);

    /* KeyEncryptionAlgorithmIdentifier, only support RSA now */
    if (keyEncAlgo != RSAk)
        return ALGO_ID_E;

    keyEncAlgSz = SetAlgoID(keyEncAlgo, keyAlgArray, keyType, 0);

    /* EncryptedKey */
    InitRsaKey(&pubKey, 0);
    if (RsaPublicKeyDecode(decoded.publicKey, &idx, &pubKey,
                           decoded.pubKeySize) < 0) {
        CYASSL_MSG("ASN RSA key decode error");
        return PUBLIC_KEY_E;
    }

    *keyEncSz = RsaPublicEncrypt(contentKeyPlain, blockKeySz, contentKeyEnc,
                                 MAX_ENCRYPTED_KEY_SZ, &pubKey, rng);
    if (*keyEncSz < 0) {
        CYASSL_MSG("RSA Public Encrypt failed");
        return *keyEncSz;
    }

    encKeyOctetStrSz = SetOctetString(*keyEncSz, encKeyOctetStr);

    /* RecipientInfo */
    recipSeqSz = SetSequence(verSz + issuerSerialSeqSz + issuerSeqSz +
                             issuerSz + snSz + keyEncAlgSz + encKeyOctetStrSz +
                             *keyEncSz, recipSeq);

    if (recipSeqSz + verSz + issuerSerialSeqSz + issuerSeqSz + snSz +
        keyEncAlgSz + encKeyOctetStrSz + *keyEncSz > (int)outSz) {
        CYASSL_MSG("RecipientInfo output buffer too small");
        return BUFFER_E;
    }

    XMEMCPY(out + totalSz, recipSeq, recipSeqSz);
    totalSz += recipSeqSz;
    XMEMCPY(out + totalSz, ver, verSz);
    totalSz += verSz;
    XMEMCPY(out + totalSz, issuerSerialSeq, issuerSerialSeqSz);
    totalSz += issuerSerialSeqSz;
    XMEMCPY(out + totalSz, issuerSeq, issuerSeqSz);
    totalSz += issuerSeqSz;
    XMEMCPY(out + totalSz, decoded.issuerRaw, issuerSz);
    totalSz += issuerSz;
    XMEMCPY(out + totalSz, serial, snSz);
    totalSz += snSz;
    XMEMCPY(out + totalSz, keyAlgArray, keyEncAlgSz);
    totalSz += keyEncAlgSz;
    XMEMCPY(out + totalSz, encKeyOctetStr, encKeyOctetStrSz);
    totalSz += encKeyOctetStrSz;
    XMEMCPY(out + totalSz, contentKeyEnc, *keyEncSz);
    totalSz += *keyEncSz;

    FreeDecodedCert(&decoded);

    return totalSz;
}


int PKCS7_EncodeEnvelopeData(PKCS7* pkcs7, byte* output, word32 outputSz)
{
    int i, idx = 0;
    int totalSz = 0, padSz = 0, desOutSz = 0;

    int contentInfoSeqSz, outerContentTypeSz, outerContentSz;
    byte contentInfoSeq[MAX_SEQ_SZ];
    byte outerContentType[MAX_ALGO_SZ];
    byte outerContent[MAX_SEQ_SZ];

    int envDataSeqSz, verSz;
    byte envDataSeq[MAX_SEQ_SZ];
    byte ver[MAX_VERSION_SZ];

    RNG rng;
    int contentKeyEncSz, blockKeySz;
    int dynamicFlag = 0;
    byte contentKeyPlain[MAX_CONTENT_KEY_LEN];
    byte contentKeyEnc[MAX_ENCRYPTED_KEY_SZ];
    byte* plain;
    byte* encryptedContent;

    int recipSz, recipSetSz;
    byte recip[MAX_RECIP_SZ];
    byte recipSet[MAX_SET_SZ];

    int encContentOctetSz, encContentSeqSz, contentTypeSz, contentEncAlgoSz;
    byte encContentSeq[MAX_SEQ_SZ];
    byte contentType[MAX_ALGO_SZ];
    byte contentEncAlgo[MAX_ALGO_SZ];
    byte encContentOctet[MAX_OCTET_STR_SZ];

    switch (pkcs7->encryptOID) {
        case DESb:
            blockKeySz = DES_KEYLEN;
            break;

        case DES3b:
            blockKeySz = DES3_KEYLEN;
            break;

        default:
            CYASSL_MSG("Unsupported content cipher type");
            return ALGO_ID_E;
    };

    /* outer content type */
    outerContentTypeSz = SetContentType(ENVELOPED_DATA, outerContentType);

    /* version */
    verSz = SetMyVersion(0, ver, 0);

    /* generate random content enc key */
    InitRng(&rng);
    RNG_GenerateBlock(&rng, contentKeyPlain, blockKeySz);

    /* build RecipientInfo, only handle 1 for now */
    recipSz = CreateRecipientInfo(pkcs7->singleCert, pkcs7->singleCertSz, RSAk,
                                  blockKeySz, &rng, contentKeyPlain,
                                  contentKeyEnc, &contentKeyEncSz, recip,
                                  MAX_RECIP_SZ);

    if (recipSz < 0) {
        CYASSL_MSG("Failed to create RecipientInfo");
        return recipSz;
    }
    recipSetSz = SetSet(recipSz, recipSet);

    /* EncryptedContentInfo */
    contentTypeSz = SetContentType(pkcs7->contentOID, contentType);
    contentEncAlgoSz = SetAlgoID(pkcs7->encryptOID, contentEncAlgo,
                                 blkType, 0);

    /* allocate memory for encrypted content, pad if necessary */
    padSz = DES_BLOCK_SIZE - (pkcs7->contentSz % DES_BLOCK_SIZE);
    desOutSz = pkcs7->contentSz + padSz;

    if (padSz != 0) {
        plain = XMALLOC(desOutSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (plain == NULL) {
            return MEMORY_E;
        }
        XMEMCPY(plain, pkcs7->content, pkcs7->contentSz);
        dynamicFlag = 1;

        for (i = 0; i < padSz; i++) {
            plain[pkcs7->contentSz + i + 1] = padSz;
        }

    } else {
        plain = pkcs7->content;
        desOutSz = pkcs7->contentSz;
    }

    encryptedContent = XMALLOC(desOutSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (encryptedContent == NULL) {
        if (dynamicFlag)
            XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    byte tmpIv[blockKeySz];
    if (pkcs7->encryptOID == DESb) {
        Des des;
        RNG_GenerateBlock(&rng, tmpIv, (word32)sizeof(tmpIv));
        Des_SetKey(&des, contentKeyPlain, tmpIv, DES_ENCRYPTION);
        Des_CbcEncrypt(&des, encryptedContent, plain, desOutSz);

    } else if (pkcs7->encryptOID == DES3b) {
        Des3 des3;
        RNG_GenerateBlock(&rng, tmpIv, (word32)sizeof(tmpIv));
        Des3_SetKey(&des3, contentKeyPlain, tmpIv, DES_ENCRYPTION);
        Des3_CbcEncrypt(&des3, encryptedContent, plain, desOutSz);
    }

    encContentOctetSz = SetOctetString(desOutSz, encContentOctet);

    encContentSeqSz = SetSequence(contentTypeSz + contentEncAlgoSz +
                                  encContentOctetSz + desOutSz, encContentSeq);

    /* keep track of sizes for outer wrapper layering */
    totalSz = verSz + recipSetSz + recipSz + encContentSeqSz + contentTypeSz +
              contentEncAlgoSz + encContentOctetSz + desOutSz;

    /* EnvelopedData */
    envDataSeqSz = SetSequence(totalSz, envDataSeq);
    totalSz += envDataSeqSz;

    /* outer content */
    outerContent[0] = (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0);
    outerContentSz = 1 + SetLength(totalSz, outerContent + 1);
    totalSz += outerContentTypeSz;
    totalSz += outerContentSz;

    /* ContentInfo */
    contentInfoSeqSz = SetSequence(totalSz, contentInfoSeq);
    totalSz += contentInfoSeqSz;

    if (totalSz > (int)outputSz) {
        CYASSL_MSG("Pkcs7_encrypt output buffer too small");
        XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (dynamicFlag)
            XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return BUFFER_E;
    }

    XMEMCPY(output + idx, contentInfoSeq, contentInfoSeqSz);
    idx += contentInfoSeqSz;
    XMEMCPY(output + idx, outerContentType, outerContentTypeSz);
    idx += outerContentTypeSz;
    XMEMCPY(output + idx, outerContent, outerContentSz);
    idx += outerContentSz;
    XMEMCPY(output + idx, envDataSeq, envDataSeqSz);
    idx += envDataSeqSz;
    XMEMCPY(output + idx, ver, verSz);
    idx += verSz;
    XMEMCPY(output + idx, recipSet, recipSetSz);
    idx += recipSetSz;
    XMEMCPY(output + idx, recip, recipSz);
    idx += recipSz;
    XMEMCPY(output + idx, encContentSeq, encContentSeqSz);
    idx += encContentSeqSz;
    XMEMCPY(output + idx, contentType, contentTypeSz);
    idx += contentTypeSz;
    XMEMCPY(output + idx, contentEncAlgo, contentEncAlgoSz);
    idx += contentEncAlgoSz;
    XMEMCPY(output + idx, encContentOctet, encContentOctetSz);
    idx += encContentOctetSz;
    XMEMCPY(output + idx, encryptedContent, desOutSz);
    idx += desOutSz;

#ifdef NO_RC4
    FreeRng(&rng);
#endif
    if (dynamicFlag)
        XFREE(plain, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
    XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return idx;
}


#else  /* HAVE_PKCS7 */


#ifdef _MSC_VER
    /* 4206 warning for blank file */
    #pragma warning(disable: 4206)
#endif


#endif /* HAVE_PKCS7 */

