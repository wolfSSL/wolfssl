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

int GetContentType(const byte* input, word32* inOutIdx, word32* oid,
                   word32 maxIdx)
{
    int length;
    word32 i = *inOutIdx;
    byte b;
    *oid = 0;

    CYASSL_ENTER("GetContentType");

    b = input[i++];
    if (b != ASN_OBJECT_ID)
        return ASN_OBJECT_ID_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    while(length--) {
        *oid += input[i];
        i++;
    }

    *inOutIdx = i;

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
    if (keyEncAlgSz == 0)
        return BAD_FUNC_ARG;

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

    if (pkcs7 == NULL || pkcs7->content == NULL || pkcs7->contentSz == 0 ||
        pkcs7->encryptOID == 0 || pkcs7->singleCert == NULL)
        return BAD_FUNC_ARG;

    if (output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;

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

    /* generate random content encryption key */
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
    if (contentTypeSz == 0)
        return BAD_FUNC_ARG;

    contentEncAlgoSz = SetAlgoID(pkcs7->encryptOID, contentEncAlgo,
                                 blkType, 0);
    if (contentEncAlgoSz == 0)
        return BAD_FUNC_ARG;

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
            plain[pkcs7->contentSz + i] = padSz;
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

    /* use NULL iv for now */
    byte tmpIv[blockKeySz];
    XMEMSET(tmpIv, 0, sizeof(tmpIv));

    if (pkcs7->encryptOID == DESb) {
        Des des;
        Des_SetKey(&des, contentKeyPlain, tmpIv, DES_ENCRYPTION);
        Des_CbcEncrypt(&des, encryptedContent, plain, desOutSz);

    } else if (pkcs7->encryptOID == DES3b) {
        Des3 des3;
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

    XMEMSET(contentKeyPlain, 0, MAX_CONTENT_KEY_LEN);
    XMEMSET(contentKeyEnc,   0, MAX_ENCRYPTED_KEY_SZ);

    if (dynamicFlag)
        XFREE(plain, NULL, DYNAMMIC_TYPE_TMP_BUFFER);
    XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return idx;
}

CYASSL_API int PKCS7_DecodeEnvelopedData(PKCS7* pkcs7, byte* pkiMsg,
                                         word32 pkiMsgSz, byte* output,
                                         word32 outputSz)
{
    int recipFound = 0;
    int ret, version, length;
    word32 savedIdx = 0, idx = 0;
    word32 contentType, encOID;
    byte   issuerHash[SHA_DIGEST_SIZE];
    mp_int serialNum;

    DecodedCert decoded;

    int encryptedKeySz, keySz;
    byte tmpIv[DES3_KEYLEN];
    byte encryptedKey[MAX_ENCRYPTED_KEY_SZ];
    byte* decryptedKey = NULL;

    RsaKey privKey;
    int encryptedContentSz;
    byte padLen;
    byte* encryptedContent = NULL;

    if (pkcs7 == NULL || pkcs7->singleCert == NULL ||
        pkcs7->singleCertSz == 0 || pkcs7->privateKey == NULL ||
        pkcs7->privKeySize == 0)
        return BAD_FUNC_ARG;

    if (pkiMsg == NULL || pkiMsgSz == 0 ||
        output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;

    /* parse recipient cert */
    InitDecodedCert(&decoded, pkcs7->singleCert, pkcs7->singleCertSz, 0);
    ret = ParseCert(&decoded, CA_TYPE, NO_VERIFY, 0);
    if (ret < 0) {
        FreeDecodedCert(&decoded);
        return ret;
    }

    /* load private key */
    InitRsaKey(&privKey, 0);
    ret = RsaPrivateKeyDecode(pkcs7->privateKey, &idx, &privKey,
                              pkcs7->privKeySize);
    if (ret != 0) {
        CYASSL_MSG("Failed to decode RSA private key");
        return ret;
    }

    idx = 0;

    /* read past ContentInfo, verify type */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (GetContentType(pkiMsg, &idx, &contentType, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (contentType != ENVELOPED_DATA) {
        CYASSL_MSG("PKCS#7 input not of type EnvelopedData");
        return PKCS7_OID_E;
    }

    if (pkiMsg[idx++] != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* remove EnvelopedData */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(pkiMsg, &idx, &version) < 0)
        return ASN_PARSE_E;

    if (version != 0) {
        CYASSL_MSG("PKCS#7 envelopedData needs to be of version 0");
        return ASN_VERSION_E;
    }

    /* walk through RecipientInfo set, find correct recipient */
    if (GetSet(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    savedIdx = idx;
    recipFound = 0;

    /* when looking for next recipient, use first sequence and version to
     * indicate there is another, if not, move on */
    while(recipFound == 0) {

        /* remove RecipientInfo */
        if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0) {
            if (recipFound == 0) {
                return ASN_PARSE_E;
            } else {
                idx = savedIdx;
                break;
            }
        }

        if (GetMyVersion(pkiMsg, &idx, &version) < 0) {
            if (recipFound == 0) {
                return ASN_PARSE_E;
            } else {
                idx = savedIdx;
                break;
            }
        }

        if (version != 0)
            return ASN_VERSION_E;

        /* remove IssuerAndSerialNumber */
        if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        if (GetNameHash(pkiMsg, &idx, issuerHash, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        if (XMEMCMP(issuerHash, decoded.issuerHash, SHA_DIGEST_SIZE) == 0) {
            recipFound = 1;
        }

        if (GetInt(&serialNum, pkiMsg, &idx, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        if (GetAlgoId(pkiMsg, &idx, &encOID, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        if (encOID != RSAk)
            return ALGO_ID_E;

        /* read encryptedKey */
        if (pkiMsg[idx++] != ASN_OCTET_STRING)
            return ASN_PARSE_E;

        if (GetLength(pkiMsg, &idx, &encryptedKeySz, pkiMsgSz) < 0)
            return ASN_PARSE_E;

        if (recipFound == 1)
            XMEMCPY(encryptedKey, &pkiMsg[idx], encryptedKeySz);
        idx += encryptedKeySz;

        /* update good idx */
        savedIdx = idx;
    }

    if (recipFound == 0) {
        CYASSL_MSG("No recipient found in envelopedData that matches input");
        return PKCS7_RECIP_E;
    }

    /* remove EncryptedContentInfo */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (GetContentType(pkiMsg, &idx, &contentType, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (GetAlgoId(pkiMsg, &idx, &encOID, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* read encryptedContent */
    if (pkiMsg[idx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, &idx, &encryptedContentSz, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    encryptedContent = XMALLOC(encryptedContentSz, NULL,
                               DYNAMIC_TYPE_TMP_BUFFER);

    XMEMCPY(encryptedContent, &pkiMsg[idx], encryptedContentSz);

    /* decrypt encryptedKey */
    keySz = RsaPrivateDecryptInline(encryptedKey, encryptedKeySz,
                                    &decryptedKey, &privKey);
    if (keySz < 0)
        return keySz;

    /* decrypt encryptedContent, using NULL iv for now */
    XMEMSET(tmpIv, 0, sizeof(tmpIv));

    if (encOID == DESb) {
        Des des;
        Des_SetKey(&des, decryptedKey, tmpIv, DES_DECRYPTION);
        Des_CbcDecrypt(&des, encryptedContent, encryptedContent,
                       encryptedContentSz);
    } else if (encOID == DES3b) {
        Des3 des;
        Des3_SetKey(&des, decryptedKey, tmpIv, DES_DECRYPTION);
        Des3_CbcDecrypt(&des, encryptedContent, encryptedContent,
                       encryptedContentSz);
    } else {
        CYASSL_MSG("Unsupported content encryption OID type");
        return ALGO_ID_E;
    }

    padLen = encryptedContent[encryptedContentSz-1];

    /* copy plaintext to output */
    XMEMCPY(output, encryptedContent, encryptedContentSz - padLen);

    /* free memory, zero out keys */
    XMEMSET(encryptedKey, 0, MAX_ENCRYPTED_KEY_SZ);
    XMEMSET(encryptedContent, 0, encryptedContentSz);
    XFREE(encryptedContent, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return encryptedContentSz - padLen;
}


#else  /* HAVE_PKCS7 */


#ifdef _MSC_VER
    /* 4206 warning for blank file */
    #pragma warning(disable: 4206)
#endif


#endif /* HAVE_PKCS7 */

