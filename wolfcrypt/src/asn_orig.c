/* asn_orig.c
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

/*
 * Original (non-template) ASN.1 implementations.
 * This file is included from asn.c when building without WOLFSSL_ASN_TEMPLATE.
 * It must not be compiled as a separate translation unit.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFSSL_ASN_ORIG_INCLUDED
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning asn_orig.c does not need to be compiled separately from asn.c
    #endif
#else

/* Forward declarations for static functions defined later in this file. */
static int SkipObjectId(const byte* input, word32* inOutIdx, word32 maxIdx);
#ifndef NO_DSA
static WC_INLINE void FreeTmpDsas(byte** tmps, void* heap, int ints);
#endif
#ifndef NO_CERTS
static int GetCertHeader(DecodedCert* cert);
static int GetDate(DecodedCert* cert, int dateType, int verify, int maxIdx);
static int GetValidity(DecodedCert* cert, int verify, int maxIdx);
#endif
static word32 SetOctetString8Bit(word32 len, byte* output);
static word32 SetDigest(const byte* digest, word32 digSz, byte* output);
#ifndef NO_CERTS
static void AddAltName(DecodedCert* cert, DNS_entry* dnsEntry);
#if defined(WOLFSSL_SEP)
static int DecodeSepHwAltName(DecodedCert* cert, const byte* input, word32* idxIn, word32 sz);
#endif
static int DecodeConstructedOtherName(DecodedCert* cert, const byte* input, word32* idx, word32 sz, int oid);
#ifdef WOLFSSL_CERT_GEN
#ifdef WOLFSSL_CERT_REQ
static word32 SetPrintableString(word32 len, byte* output);
static word32 SetUTF8String(word32 len, byte* output);
#endif
static int CopyValidity(byte* output, Cert* cert);
static int SetExtensions(byte* out, word32 outSz, int *IdxInOut, const byte* ext, int extSz);
static int SetExtensionsHeader(byte* out, word32 outSz, word32 extSz);
static int SetCaWithPathLen(byte* out, word32 outSz, byte pathLen);
static int SetCaEx(byte* out, word32 outSz, byte isCa);
static int SetCa(byte* out, word32 outSz);
static int SetBC(byte* out, word32 outSz);
#ifdef WOLFSSL_CERT_EXT
static int SetOidValue(byte* out, word32 outSz, const byte *oid, word32 oidSz, byte *in, word32 inSz);
static int SetSKID(byte* output, word32 outSz, const byte *input, word32 length);
static int SetAKID(byte* output, word32 outSz, byte *input, word32 length, byte rawAkid);
static int SetKeyUsage(byte* output, word32 outSz, word16 input);
static int SetOjectIdValue(byte* output, word32 outSz, word32* idx, const byte* oid, word32 oidSz);
#ifndef IGNORE_NETSCAPE_CERT_TYPE
static int SetNsCertType(Cert* cert, byte* output, word32 outSz, byte input);
#endif
static int SetCRLInfo(Cert* cert, byte* output, word32 outSz, byte* input, int inSz);
#endif
#ifdef WOLFSSL_ALT_NAMES
static int SetAltNames(byte *output, word32 outSz, const byte *input, word32 length, int critical);
#endif
#ifdef WOLFSSL_CERT_REQ
static word32 SetReqAttribSingle(byte* output, word32* idx, char* attr, word32 attrSz, const byte* oid, word32 oidSz, byte printable, word32 extSz);
static int SetReqAttrib(byte* output, Cert* cert, word32 extSz);
#ifdef WOLFSSL_CUSTOM_OID
static int SetCustomObjectId(Cert* cert, byte* output, word32 outSz, CertOidField* custom);
#endif
#endif
#endif
#endif
#if defined(HAVE_ECC) || !defined(NO_DSA)
static word32 is_leading_bit_set(const byte* input, word32 sz);
static word32 trim_leading_zeros(const byte** input, word32 sz);
#endif
#ifdef HAVE_ECC
#ifdef WOLFSSL_CUSTOM_CURVES
static int ASNToHexString(const byte* input, word32* inOutIdx, char** out, word32 inSz, void* heap, int heapType);
static int EccKeyParamCopy(char** dst, char* src, void* heap);
#endif
#endif
#if (defined(HAVE_OCSP) || defined(HAVE_CRL)) && !defined(WOLFCRYPT_ONLY)
static int GetBasicDate(const byte* source, word32* idx, byte* date, byte* format, int maxIdx);
#endif
#if defined(HAVE_OCSP) && !defined(WOLFCRYPT_ONLY)
static int GetEnumerated(const byte* input, word32* inOutIdx, int *value, int sz);
#endif

int GetObjectId(const byte* input, word32* inOutIdx, word32* oid,
                                  word32 oidType, word32 maxIdx)
{
    int ret, length;

    WOLFSSL_ENTER("GetObjectId");

    ret = GetASNObjectId(input, inOutIdx, &length, maxIdx);
    if (ret != 0)
        return ret;

    return GetOID(input, inOutIdx, oid, oidType, length);
}

static int SkipObjectId(const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 idx = *inOutIdx;
    int    length;
    int ret;

    ret = GetASNObjectId(input, &idx, &length, maxIdx);
    if (ret != 0)
        return ret;

    idx += (word32)length;
    *inOutIdx = idx;

    return 0;
}

static int GetAlgoIdImpl(const byte* input, word32* inOutIdx, word32* oid,
                     word32 oidType, word32 maxIdx, byte *absentParams)
{
    int    length;
    word32 idx = *inOutIdx;
    int    ret;
    *oid = 0;

    WOLFSSL_ENTER("GetAlgoId");

    if (GetSequence(input, &idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if (GetObjectId(input, &idx, oid, oidType, maxIdx) < 0)
        return ASN_OBJECT_ID_E;

    /* could have NULL tag and 0 terminator, but may not */
    if (idx < maxIdx) {
        word32 localIdx = idx; /*use localIdx to not advance when checking tag*/
        byte   tag;

        if (GetASNTag(input, &localIdx, &tag, maxIdx) == 0) {
            if (tag == ASN_TAG_NULL) {
                ret = GetASNNull(input, &idx, maxIdx);
                if (ret != 0)
                    return ret;

                if (absentParams != NULL) {
                    *absentParams = FALSE;
                }
            }
        }
    }

    *inOutIdx = idx;

    return 0;
}

#ifndef NO_RSA
static int _RsaPrivateKeyDecode(const byte* input, word32* inOutIdx,
    RsaKey* key, int* keySz, word32 inSz)
{
    int version, length;
    word32 algId = 0;
    int i;

    if (inOutIdx == NULL || input == NULL || (key == NULL && keySz == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* if has pkcs8 header skip it */
    if (ToTraditionalInline_ex(input, inOutIdx, inSz, &algId) < 0) {
        /* ignore error, did not have pkcs8 header */
    }

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version, inSz) < 0)
        return ASN_PARSE_E;

    if (key == NULL) {
        /* Modulus */
        if (GetASNInt(input, inOutIdx, keySz, inSz) < 0) {
            return ASN_PARSE_E;
        }
        *inOutIdx += (word32)*keySz;
        for (i = 1; i < RSA_INTS; i++) {
            if (SkipInt(input, inOutIdx, inSz) < 0) {
                return ASN_RSA_KEY_E;
            }
        }
    }
    else {
        key->type = RSA_PRIVATE;

    #ifdef WOLFSSL_CHECK_MEM_ZERO
        mp_memzero_add("Decode RSA key d", &key->d);
        mp_memzero_add("Decode RSA key p", &key->p);
        mp_memzero_add("Decode RSA key q", &key->q);
    #if (defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
        !defined(RSA_LOW_MEM)) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
        mp_memzero_add("Decode RSA key dP", &key->dP);
        mp_memzero_add("Decode RSA key dQ", &key->dQ);
        mp_memzero_add("Decode RSA key u", &key->u);
    #endif
    #endif

        /* Extract all public fields. */
        for (i = 0; i < RSA_INT_CNT; i++) {
            if (GetInt(GetRsaInt(key, i),  input, inOutIdx, inSz) < 0) {
                for (i--; i >= 0; i--) {
                    mp_clear(GetRsaInt(key, i));
                }
                return ASN_RSA_KEY_E;
            }
         }
    #if RSA_INT_CNT != RSA_MAX_INT_CNT
        for (; i < RSA_MAX_INT_CNT; i++) {
             if (SkipInt(input, inOutIdx, inSz) < 0) {
                for (i = RSA_INT_CNT - 1; i >= 0; i--) {
                    mp_clear(GetRsaInt(key, i));
                }
                return ASN_RSA_KEY_E;
            }
         }
   #endif

    #if defined(WOLFSSL_XILINX_CRYPT) || defined(WOLFSSL_CRYPTOCELL)
        if (wc_InitRsaHw(key) != 0) {
            return BAD_STATE_E;
        }
    #endif
    }

    return 0;
}

#endif
int ToTraditionalInline_ex2(const byte* input, word32* inOutIdx, word32 sz,
                            word32* algId, word32* eccOid)
{
    word32 idx;
    int    version, length;
    int    ret;
    byte   tag;

    if (input == NULL || inOutIdx == NULL)
        return BAD_FUNC_ARG;

    idx = *inOutIdx;

    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, &idx, &version, sz) < 0)
        return ASN_PARSE_E;

    if (GetAlgoId(input, &idx, algId, oidKeyType, sz) < 0)
        return ASN_PARSE_E;

    if (GetASNTag(input, &idx, &tag, sz) < 0)
        return ASN_PARSE_E;
    idx = idx - 1; /* reset idx after finding tag */

#if defined(WC_RSA_PSS) && !defined(NO_RSA)
    if (*algId == RSAPSSk && tag == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
        word32 seqIdx = idx;
        int seqLen;
        /* Not set when -1. */
        enum wc_HashType hash = WC_HASH_TYPE_NONE;
        int mgf = -1;
        int saltLen = 0;

        if (GetSequence(input, &idx, &seqLen, sz) < 0) {
            return ASN_PARSE_E;
        }
        /* Get the private key parameters. */
        ret = DecodeRsaPssParams(input + seqIdx,
            seqLen + idx - seqIdx, &hash, &mgf, &saltLen);
        if (ret != 0) {
            return ASN_PARSE_E;
        }
        /* TODO: store parameters so that usage can be checked. */
        idx += seqLen;
    }
#endif /* WC_RSA_PSS && !NO_RSA */

    if (tag == ASN_OBJECT_ID) {
        if ((*algId == ECDSAk) && (eccOid != NULL)) {
            if (GetObjectId(input, &idx, eccOid, oidCurveType, sz) < 0)
                return ASN_PARSE_E;
        }
        else {
            if (SkipObjectId(input, &idx, sz) < 0)
                return ASN_PARSE_E;
        }
    }

    ret = GetOctetString(input, &idx, &length, sz);
    if (ret < 0) {
        if (ret == WC_NO_ERR_TRACE(BUFFER_E))
            return ASN_PARSE_E;
        /* Some private keys don't expect an octet string - ignore error. */
        WOLFSSL_MSG("Couldn't find Octet string");
        length = 0;
    }

    *inOutIdx = idx;

    return length;
}

#if defined(HAVE_PKCS8)
int wc_CreatePKCS8Key(byte* out, word32* outSz, byte* key, word32 keySz,
        int algoID, const byte* curveOID, word32 oidSz)
{
    word32 keyIdx = 0;
    word32 tmpSz  = 0;
    word32 sz;
    word32 tmpAlgId = 0;

    /* If out is NULL then return the max size needed
     * + 2 for ASN_OBJECT_ID and ASN_OCTET_STRING tags */
    if (out == NULL && outSz != NULL) {
        *outSz = keySz + MAX_SEQ_SZ + MAX_VERSION_SZ + MAX_ALGO_SZ
                 + MAX_LENGTH_SZ + MAX_LENGTH_SZ + 2;

        if (curveOID != NULL)
            *outSz += oidSz + MAX_LENGTH_SZ + 1;

        WOLFSSL_MSG("Checking size of PKCS8");

        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    WOLFSSL_ENTER("wc_CreatePKCS8Key");

    if (key == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* check the buffer has enough room for largest possible size */
    if (curveOID != NULL) {
        sz = keySz + MAX_SEQ_SZ + MAX_VERSION_SZ + MAX_ALGO_SZ + MAX_LENGTH_SZ +
            MAX_LENGTH_SZ + 3 + oidSz + MAX_LENGTH_SZ;
        if ((keySz > sz) || (oidSz > sz) || (*outSz < sz))
            return BUFFER_E;
    }
    else {
        oidSz = 0; /* with no curveOID oid size must be 0 */
        sz= keySz + MAX_SEQ_SZ + MAX_VERSION_SZ + MAX_ALGO_SZ + MAX_LENGTH_SZ +
            MAX_LENGTH_SZ + 2;
        if ((keySz > sz) || (*outSz < sz))
            return BUFFER_E;
    }

    /* sanity check: make sure the key doesn't already have a PKCS 8 header */
    if (ToTraditionalInline_ex(key, &keyIdx, keySz, &tmpAlgId) >= 0) {
        (void)tmpAlgId;
        return ASN_PARSE_E;
    }

    /* PrivateKeyInfo ::= SEQUENCE */
    keyIdx = MAX_SEQ_SZ; /* save room for sequence */

    /*  version Version
     *  no header information just INTEGER */
    sz = (word32)SetMyVersion(PKCS8v0, out + keyIdx, 0);
    tmpSz += sz; keyIdx += sz;
    /*  privateKeyAlgorithm PrivateKeyAlgorithmIdentifier */
    sz = 0; /* set sz to 0 and get privateKey oid buffer size needed */
    if (curveOID != NULL && oidSz > 0) {
        byte buf[MAX_LENGTH_SZ];
        sz = SetLength(oidSz, buf);
        sz += 1; /* plus one for ASN object id */
    }
    sz = (word32)SetAlgoID(algoID, out + keyIdx, oidKeyType, (int)(oidSz + sz));
    tmpSz += sz; keyIdx += sz;

    /*  privateKey          PrivateKey *
     * pkcs8 ecc uses slightly different format. Places curve oid in
     * buffer */
    if (curveOID != NULL && oidSz > 0) {
        sz = (word32)SetObjectId((int)oidSz, out + keyIdx);
        keyIdx += sz; tmpSz += sz;
        XMEMCPY(out + keyIdx, curveOID, oidSz);
        keyIdx += oidSz; tmpSz += oidSz;
    }

    sz = (word32)SetOctetString(keySz, out + keyIdx);
    keyIdx += sz; tmpSz += sz;
    XMEMCPY(out + keyIdx, key, keySz);
    tmpSz += keySz;

    /*  attributes          optional
     * No attributes currently added */

    /* rewind and add sequence */
    sz = SetSequence(tmpSz, out);
    XMEMMOVE(out + sz, out + MAX_SEQ_SZ, tmpSz);

    *outSz = tmpSz + sz;
    return (int)(tmpSz + sz);
}

#endif
#ifndef NO_PWDBASED
#ifdef HAVE_PKCS8
int DecryptContent(byte* input, word32 sz, const char* password, int passwordSz)
{
    word32 inOutIdx = 0, seqEnd, oid, shaOid = 0, seqPkcs5End = sz;
    int    ret = 0, first, second, length = 0, version, saltSz, id = 0;
    int    iterations = 0, keySz = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte*  salt = NULL;
    byte*  cbcIv = NULL;
#else
    byte   salt[MAX_SALT_SIZE];
    byte   cbcIv[MAX_IV_SIZE];
#endif
    byte   tag;

    if (passwordSz < 0) {
        WOLFSSL_MSG("Bad password size");
        return BAD_FUNC_ARG;
    }

    if (GetAlgoId(input, &inOutIdx, &oid, oidIgnoreType, sz) < 0) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    first  = input[inOutIdx - 2];   /* PKCS version always 2nd to last byte */
    second = input[inOutIdx - 1];   /* version.algo, algo id last byte */

    if (CheckAlgo(first, second, &id, &version, NULL) < 0) {
        ERROR_OUT(ASN_INPUT_E, exit_dc); /* Algo ID error */
    }

    if (version == PKCS5v2) {
        if (GetSequence(input, &inOutIdx, &length, sz) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }
        seqPkcs5End = inOutIdx + length;

        if (GetAlgoId(input, &inOutIdx, &oid, oidKdfType, sz) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        if (oid != PBKDF2_OID) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }
    }

    if (GetSequence(input, &inOutIdx, &length, sz) <= 0) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }
    /* Find the end of this SEQUENCE so we can check for the OPTIONAL and
     * DEFAULT items. */
    seqEnd = inOutIdx + (word32)length;

    ret = GetOctetString(input, &inOutIdx, &saltSz, seqEnd);
    if (ret < 0)
        goto exit_dc;

    if (saltSz > MAX_SALT_SIZE) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    WC_ALLOC_VAR_EX(salt, byte, MAX_SALT_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ERROR_OUT(MEMORY_E,exit_dc));

    XMEMCPY(salt, &input[inOutIdx], (size_t)saltSz);
    inOutIdx += (word32)saltSz;

    if (GetShortInt(input, &inOutIdx, &iterations, seqEnd) < 0) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    /* OPTIONAL key length */
    if (seqEnd > inOutIdx) {
        word32 localIdx = inOutIdx;

        if (GetASNTag(input, &localIdx, &tag, seqEnd) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        if (tag == ASN_INTEGER &&
                GetShortInt(input, &inOutIdx, &keySz, seqEnd) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }
    }

    /* DEFAULT HMAC is SHA-1 */
    if (seqEnd > inOutIdx) {
        if (GetAlgoId(input, &inOutIdx, &oid, oidHmacType, seqEnd) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        shaOid = oid;
    }

    WC_ALLOC_VAR_EX(cbcIv, byte, MAX_IV_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ERROR_OUT(MEMORY_E,exit_dc));

    if (version == PKCS5v2) {
        /* get encryption algo */
        if (GetAlgoId(input, &inOutIdx, &oid, oidBlkType, seqPkcs5End) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        if (CheckAlgoV2((int)oid, &id, NULL) < 0) {
            ERROR_OUT(ASN_PARSE_E, exit_dc); /* PKCS v2 algo id error */
        }

        if (shaOid == 0)
            shaOid = oid;

        ret = GetOctetString(input, &inOutIdx, &length, seqPkcs5End);
        if (ret < 0)
            goto exit_dc;

        if (length > MAX_IV_SIZE) {
            ERROR_OUT(ASN_PARSE_E, exit_dc);
        }

        XMEMCPY(cbcIv, &input[inOutIdx], (size_t)length);
        inOutIdx += (word32)length;
    }

    if (GetASNTag(input, &inOutIdx, &tag, sz) < 0) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    if (tag != (ASN_CONTEXT_SPECIFIC | 0) && tag != ASN_OCTET_STRING) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    if (GetLength(input, &inOutIdx, &length, sz) < 0) {
        ERROR_OUT(ASN_PARSE_E, exit_dc);
    }

    ret = wc_CryptKey(password, passwordSz, salt, saltSz, iterations, id,
                   input + inOutIdx, length, version, cbcIv, 0, (int)shaOid);

exit_dc:
    WC_FREE_VAR_EX(salt, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WC_FREE_VAR_EX(cbcIv, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret == 0) {
        XMEMMOVE(input, input + inOutIdx, (size_t)length);
        ret = length;
    }

    return ret;
}

#endif
#ifdef HAVE_PKCS12
int EncryptContent(byte* input, word32 inputSz, byte* out, word32* outSz,
        const char* password, int passwordSz, int vPKCS, int vAlgo,
        int encAlgId, byte* salt, word32 saltSz, int itt, int hmacOid,
        WC_RNG* rng, void* heap)
{
    word32 sz;
    word32 inOutIdx = 0;
    word32 tmpIdx   = 0;
    word32 totalSz  = 0;
    word32 seqSz;
    word32 innerSz;
    int    ret;
    int    version, id = PBE_NONE, blockSz = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte*  saltTmp = NULL;
    byte*  cbcIv   = NULL;
#else
    byte   saltTmp[MAX_SALT_SIZE];
    byte   cbcIv[MAX_IV_SIZE];
#endif
    byte   seq[MAX_SEQ_SZ];
    byte   shr[MAX_SHORT_SZ];
    word32 maxShr = MAX_SHORT_SZ;
    word32 algoSz;
    const  byte* algoName;

    (void)encAlgId;
    (void)hmacOid;
    (void)heap;

    (void)EncryptContentPBES2;

    WOLFSSL_ENTER("EncryptContent");

    if (CheckAlgo(vPKCS, vAlgo, &id, &version, &blockSz) < 0)
        return ASN_INPUT_E;  /* Algo ID error */

    if (version == PKCS5v2) {
        WOLFSSL_MSG("PKCS#5 version 2 not supported yet");
        return BAD_FUNC_ARG;
    }

    if (saltSz > MAX_SALT_SIZE)
        return ASN_PARSE_E;

    if (outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* calculate size */
    /* size of constructed string at end */
    sz = wc_PkcsPad(NULL, inputSz, (word32)blockSz);
    totalSz  = ASN_TAG_SZ;
    totalSz += SetLength(sz, seq);
    totalSz += sz;

    /* size of sequence holding object id and sub sequence of salt and itt */
    algoName = OidFromId((word32)id, oidPBEType, &algoSz);
    if (algoName == NULL) {
        WOLFSSL_MSG("Unknown Algorithm");
        return 0;
    }
    innerSz = (word32)SetObjectId((int)algoSz, seq);
    innerSz += algoSz;

    /* get subsequence of salt and itt */
    if (salt == NULL || saltSz == 0) {
        sz = 8;
    }
    else {
        sz = saltSz;
    }
    seqSz  = SetOctetString(sz, seq);
    seqSz += sz;

    tmpIdx = 0;
    ret = SetShortInt(shr, &tmpIdx, (word32)itt, maxShr);
    if (ret >= 0) {
        seqSz += (word32)ret;
    }
    else {
        return ret;
    }
    innerSz += seqSz + SetSequence(seqSz, seq);
    totalSz += innerSz + SetSequence(innerSz, seq);

    if (out == NULL) {
        *outSz = totalSz;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    inOutIdx = 0;
    if (totalSz > *outSz)
        return BUFFER_E;

    inOutIdx += SetSequence(innerSz, out + inOutIdx);
    inOutIdx += (word32)SetObjectId((int)algoSz, out + inOutIdx);
    XMEMCPY(out + inOutIdx, algoName, algoSz);
    inOutIdx += algoSz;
    inOutIdx += SetSequence(seqSz, out + inOutIdx);

    /* create random salt if one not provided */
    if (salt == NULL || saltSz == 0) {
        saltSz = 8;
        WC_ALLOC_VAR_EX(saltTmp, byte, saltSz, heap, DYNAMIC_TYPE_TMP_BUFFER,
            return MEMORY_E);
        salt = saltTmp;

        if ((ret = wc_RNG_GenerateBlock(rng, saltTmp, saltSz)) != 0) {
            WOLFSSL_MSG("Error generating random salt");
            WC_FREE_VAR_EX(saltTmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
    }
    inOutIdx += SetOctetString(saltSz, out + inOutIdx);
    if (saltSz + inOutIdx > *outSz) {
        WC_FREE_VAR_EX(saltTmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return BUFFER_E;
    }
    XMEMCPY(out + inOutIdx, salt, saltSz);
    inOutIdx += saltSz;

    /* place iteration setting in buffer */
    ret = SetShortInt(out, &inOutIdx, (word32)itt, *outSz);
    if (ret < 0) {
        WC_FREE_VAR_EX(saltTmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    if (inOutIdx + 1 > *outSz) {
        WC_FREE_VAR_EX(saltTmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return BUFFER_E;
    }
    out[inOutIdx++] = ASN_CONTEXT_SPECIFIC | 0;

    /* get pad size and verify buffer room */
    sz = wc_PkcsPad(NULL, inputSz, (word32)blockSz);
    if (sz + inOutIdx > *outSz) {
        WC_FREE_VAR_EX(saltTmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return BUFFER_E;
    }
    inOutIdx += SetLength(sz, out + inOutIdx);

    /* copy input to output buffer and pad end */
    XMEMCPY(out + inOutIdx, input, inputSz);
    sz = wc_PkcsPad(out + inOutIdx, inputSz, (word32)blockSz);
#ifdef WOLFSSL_SMALL_STACK
    cbcIv = (byte*)XMALLOC(MAX_IV_SIZE, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (cbcIv == NULL) {
        XFREE(saltTmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    /* encrypt */
    if ((ret = wc_CryptKey(password, passwordSz, salt, (int)saltSz, itt, id,
                   out + inOutIdx, (int)sz, version, cbcIv, 1, 0)) < 0) {

        WC_FREE_VAR_EX(cbcIv, heap, DYNAMIC_TYPE_TMP_BUFFER);
        WC_FREE_VAR_EX(saltTmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;  /* encrypt failure */
    }

    WC_FREE_VAR_EX(cbcIv, heap, DYNAMIC_TYPE_TMP_BUFFER);
    WC_FREE_VAR_EX(saltTmp, heap, DYNAMIC_TYPE_TMP_BUFFER);

    (void)rng;

    return (int)(inOutIdx + sz);
}

#endif
#endif
#ifndef NO_RSA
#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_FSPSM_TLS)
static int RsaPublicKeyDecodeRawIndex(const byte* input, word32* inOutIdx,
                                      word32 inSz, word32* key_n,
                                      word32* key_n_len, word32* key_e,
                                      word32* key_e_len)
{
    int ret = 0;
    int length = 0;

#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
    byte b;
#endif

    if (input == NULL || inOutIdx == NULL)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
    if ((*inOutIdx + 1) > inSz)
        return BUFFER_E;

    b = input[*inOutIdx];
    if (b != ASN_INTEGER) {
        /* not from decoded cert, will have algo id, skip past */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        if (SkipObjectId(input, inOutIdx, inSz) < 0)
            return ASN_PARSE_E;

        /* Option NULL ASN.1 tag */
        if (*inOutIdx  >= inSz) {
            return BUFFER_E;
        }
        if (input[*inOutIdx] == ASN_TAG_NULL) {
            ret = GetASNNull(input, inOutIdx, inSz);
            if (ret != 0)
                return ret;
        }
        /* TODO: support RSA PSS */

        /* should have bit tag length and seq next */
        ret = CheckBitString(input, inOutIdx, NULL, inSz, 1, NULL);
        if (ret != 0)
            return ret;

        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
    }
#endif /* OPENSSL_EXTRA */

    /* Get modulus */
    ret = GetASNInt(input, inOutIdx, &length, inSz);
    *key_n += *inOutIdx;
    if (ret < 0) {
        return ASN_RSA_KEY_E;
    }
    if (key_n_len)
        *key_n_len = length;
    *inOutIdx += length;

    /* Get exponent */
    ret = GetASNInt(input, inOutIdx, &length, inSz);
    *key_e += *inOutIdx;
    if (ret < 0) {
        return ASN_RSA_KEY_E;
    }
    if (key_e_len)
        *key_e_len = length;
    return ret;
}

#endif
int wc_RsaPublicKeyDecode_ex(const byte* input, word32* inOutIdx, word32 inSz,
    const byte** n, word32* nSz, const byte** e, word32* eSz)
{
    int ret = 0;
    int length = 0;
    int firstLen = 0;
    word32 seqEndIdx = inSz;
#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
    word32 localIdx;
    byte   tag;
#endif

    if (input == NULL || inOutIdx == NULL)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

#if defined(OPENSSL_EXTRA) || defined(RSA_DECODE_EXTRA)
    localIdx = *inOutIdx;
    if (GetASNTag(input, &localIdx, &tag, inSz) < 0)
        return BUFFER_E;

    if (tag != ASN_INTEGER) {
        /* not from decoded cert, will have algo id, skip past */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        if (SkipObjectId(input, inOutIdx, inSz) < 0)
            return ASN_PARSE_E;

        /* Option NULL ASN.1 tag */
        if (*inOutIdx  >= inSz) {
            return BUFFER_E;
        }

        localIdx = *inOutIdx;
        if (GetASNTag(input, &localIdx, &tag, inSz) < 0)
            return ASN_PARSE_E;

        if (tag == ASN_TAG_NULL) {
            ret = GetASNNull(input, inOutIdx, inSz);
            if (ret != 0)
                return ret;
        }
    #ifdef WC_RSA_PSS
        /* Skip RSA PSS parameters. */
        else if (tag == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                return ASN_PARSE_E;
            *inOutIdx += length;
        }
    #endif

        /* should have bit tag length and seq next */
        ret = CheckBitString(input, inOutIdx, NULL, inSz, 1, NULL);
        if (ret != 0)
            return ret;

        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        /* Calculate where the sequence should end for public key validation */
        seqEndIdx = *inOutIdx + (word32)length;
    }
#endif /* OPENSSL_EXTRA */

    /* Get modulus */
    ret = GetASNInt(input, inOutIdx, &firstLen, seqEndIdx);
    if (ret < 0) {
        return ASN_RSA_KEY_E;
    }
    if (nSz)
        *nSz = (word32)firstLen;
    if (n)
        *n = &input[*inOutIdx];
    *inOutIdx += (word32)firstLen;

    /* Get exponent */
    ret = GetASNInt(input, inOutIdx, &length, seqEndIdx);
    if (ret < 0) {
        return ASN_RSA_KEY_E;
    }
    if (eSz)
        *eSz = (word32)length;
    if (e)
        *e = &input[*inOutIdx];
    *inOutIdx += (word32)length;

    /* Detect if this is an RSA private key being passed as public key.
     * An RSA private key has: version (small), modulus (large), exponent,
     * followed by more integers (d, p, q, etc.).
     * An RSA public key has: modulus (large), exponent, and nothing more.
     * If the first integer is small (like version 0) AND there is more data
     * remaining in the sequence, this is likely a private key. */
    if (firstLen <= MAX_VERSION_SZ && *inOutIdx < seqEndIdx) {
        /* First integer is small and there's more data - looks like
         * version field of a private key, not a modulus */
        return ASN_RSA_KEY_E;
    }

    return ret;
}

#endif
#ifndef NO_DH
int wc_DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key, word32 inSz)
{
    int ret = 0;
    int length;
#ifdef WOLFSSL_DH_EXTRA
    #if !defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    word32 oid = 0, temp = 0;
    #endif
#endif

    WOLFSSL_ENTER("wc_DhKeyDecode");

    if (inOutIdx == NULL)
        return BAD_FUNC_ARG;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

#ifdef WOLFSSL_DH_EXTRA
    #if !defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    temp = *inOutIdx;
    #endif
#endif
    /* Assume input started after 1.2.840.113549.1.3.1 dhKeyAgreement */
    if (GetInt(&key->p, input, inOutIdx, inSz) < 0) {
        ret = ASN_DH_KEY_E;
    }
    if (ret == 0 && GetInt(&key->g, input, inOutIdx, inSz) < 0) {
        mp_clear(&key->p);
        ret = ASN_DH_KEY_E;
    }

#ifdef WOLFSSL_DH_EXTRA
    #if !defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2))
    /* If ASN_DH_KEY_E: Check if input started at beginning of key */
    if (ret == WC_NO_ERR_TRACE(ASN_DH_KEY_E)) {
        *inOutIdx = temp;

        /* the version (0) - private only (for public skip) */
        if (GetASNInt(input, inOutIdx, &length, inSz) == 0) {
            *inOutIdx += (word32)length;
        }

        /* Size of dhKeyAgreement section */
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        /* Check for dhKeyAgreement */
        ret = GetObjectId(input, inOutIdx, &oid, oidKeyType, inSz);
        if (oid != DHk || ret < 0)
            return ASN_DH_KEY_E;

        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        if (GetInt(&key->p, input, inOutIdx, inSz) < 0) {
            return ASN_DH_KEY_E;
        }
        if (ret == 0 && GetInt(&key->g, input, inOutIdx, inSz) < 0) {
            mp_clear(&key->p);
            return ASN_DH_KEY_E;
        }
    }

    temp = *inOutIdx;
    ret = (CheckBitString(input, inOutIdx, &length, inSz, 0, NULL) == 0);
    if (ret > 0) {
        /* Found Bit String */
        if (GetInt(&key->pub, input, inOutIdx, inSz) == 0) {
            WOLFSSL_MSG("Found Public Key");
            ret = 0;
        }
    } else {
        *inOutIdx = temp;
        ret = (GetOctetString(input, inOutIdx, &length, inSz) >= 0);
        if (ret > 0) {
            /* Found Octet String */
            if (GetInt(&key->priv, input, inOutIdx, inSz) == 0) {
                WOLFSSL_MSG("Found Private Key");

                /* Compute public */
                ret = mp_exptmod(&key->g, &key->priv, &key->p, &key->pub);
            }
        } else {
            /* Don't use length from failed CheckBitString/GetOctetString */
            *inOutIdx = temp;
            ret = 0;
        }
    }
    #endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* WOLFSSL_DH_EXTRA */

    WOLFSSL_LEAVE("wc_DhKeyDecode", ret);

    return ret;
}

#ifdef WOLFSSL_DH_EXTRA
int wc_DhKeyToDer(DhKey* key, byte* output, word32* outSz, int exportPriv)
{
    int ret, privSz = 0, pubSz = 0;
    word32 keySz, idx, len, total;

    if (key == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* determine size */
    if (exportPriv) {
        /* octet string: priv */
        privSz = SetASNIntMP(&key->priv, -1, NULL);
        if (privSz < 0)
            return privSz;
        idx = 1 + SetLength((word32)privSz, NULL) +
            (word32)privSz; /* +1 for ASN_OCTET_STRING */
    }
    else {
        /* bit string: public */
        pubSz = SetASNIntMP(&key->pub, -1, NULL);
        if (pubSz < 0)
            return pubSz;
        idx = SetBitString((word32)pubSz, 0, NULL) + (word32)pubSz;
    }
    keySz = idx;

    /* DH Parameters sequence with P and G */
    total = 0;
    ret = wc_DhParamsToDer(key, NULL, &total);
    if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E))
        return ret;
    idx += total;

    /* object dhKeyAgreement 1.2.840.113549.1.3.1 */
    idx += (word32)SetObjectId(sizeof(keyDhOid), NULL);
    idx += (word32)sizeof(keyDhOid);
    len = idx - keySz;
    /* sequence - all but pub/priv */
    idx += SetSequence(len, NULL);
    if (exportPriv) {
        /* version: 0 (ASN_INTEGER, 0x01, 0x00) */
        idx += 3;
    }
    /* sequence */
    total = idx + SetSequence(idx, NULL);

    /* if no output, then just getting size */
    if (output == NULL) {
        *outSz = total;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    /* make sure output fits in buffer */
    if (total > *outSz) {
        return BUFFER_E;
    }
    total = idx;

    /* sequence */
    idx = SetSequence(total, output);
    if (exportPriv) {
        /* version: 0 */
        idx += (word32)SetMyVersion(0, output + idx, 0);
    }
    /* sequence - all but pub/priv */
    idx += SetSequence(len, output + idx);
    /* object dhKeyAgreement 1.2.840.113549.1.3.1 */
    idx += (word32)SetObjectId(sizeof(keyDhOid), output + idx);
    XMEMCPY(output + idx, keyDhOid, sizeof(keyDhOid));
    idx += sizeof(keyDhOid);

    /* DH Parameters sequence with P and G */
    total = *outSz - idx;
    ret = wc_DhParamsToDer(key, output + idx, &total);
    if (ret < 0)
        return ret;
    idx += total;

    /* octet string: priv */
    if (exportPriv) {
        idx += (word32)SetOctetString((word32)privSz, output + idx);
        idx += (word32)SetASNIntMP(&key->priv, -1, output + idx);
    }
    else {
        /* bit string: public */
        idx += (word32)SetBitString((word32)pubSz, 0, output + idx);
        idx += (word32)SetASNIntMP(&key->pub, -1, output + idx);
    }
    *outSz = idx;

    return (int)idx;
}

int wc_DhParamsToDer(DhKey* key, byte* output, word32* outSz)
{
    int ret;
    word32 idx, total;

    if (key == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* determine size */
    /* integer - g */
    ret = SetASNIntMP(&key->g, -1, NULL);
    if (ret < 0)
        return ret;
    idx = (word32)ret;
    /* integer - p */
    ret = SetASNIntMP(&key->p, -1, NULL);
    if (ret < 0)
        return ret;
    idx += (word32)ret;
    total = idx;
     /* sequence */
    idx += SetSequence(idx, NULL);

    if (output == NULL) {
        *outSz = idx;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }
    /* make sure output fits in buffer */
    if (idx > *outSz) {
        return BUFFER_E;
    }


    /* write DH parameters */
    /* sequence - for P and G only */
    idx = SetSequence(total, output);
    /* integer - p */
    ret = SetASNIntMP(&key->p, -1, output + idx);
    if (ret < 0)
        return ret;
    idx += (word32)ret;
    /* integer - g */
    ret = SetASNIntMP(&key->g, -1, output + idx);
    if (ret < 0)
        return ret;
    idx += (word32)ret;
    *outSz = idx;

    return (int)idx;
}

#endif
int wc_DhParamsLoad(const byte* input, word32 inSz, byte* p, word32* pInOutSz,
                 byte* g, word32* gInOutSz)
{
    word32 idx = 0;
    int    ret;
    int    length;

    if (GetSequence(input, &idx, &length, inSz) <= 0)
        return ASN_PARSE_E;

    ret = GetASNInt(input, &idx, &length, inSz);
    if (ret != 0)
        return ret;

    if (length <= (int)*pInOutSz) {
        XMEMCPY(p, &input[idx], (size_t)length);
        *pInOutSz = (word32)length;
    }
    else {
        return BUFFER_E;
    }
    idx += (word32)length;

    ret = GetASNInt(input, &idx, &length, inSz);
    if (ret != 0)
        return ret;

    if (length <= (int)*gInOutSz) {
        XMEMCPY(g, &input[idx], (size_t)length);
        *gInOutSz = (word32)length;
    }
    else {
        return BUFFER_E;
    }

    return 0;
}

#endif
#ifndef NO_DSA
int wc_DsaPublicKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key,
                          word32 inSz)
{
    int    length;
    int    ret = 0;
    word32 oid;
    word32 maxIdx;

    if (input == NULL || inOutIdx == NULL || key == NULL)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    maxIdx = (word32)(*inOutIdx + (word32)length);
    if (GetInt(&key->p,  input, inOutIdx, maxIdx) < 0 ||
        GetInt(&key->q,  input, inOutIdx, maxIdx) < 0 ||
        GetInt(&key->g,  input, inOutIdx, maxIdx) < 0 ||
        GetInt(&key->y,  input, inOutIdx, maxIdx) < 0 )
        ret = ASN_DH_KEY_E;

    if (ret != 0) {
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        ret = GetObjectId(input, inOutIdx, &oid, oidIgnoreType, inSz);
        if (ret != 0)
            return ret;

        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
            GetInt(&key->q,  input, inOutIdx, inSz) < 0 ||
            GetInt(&key->g,  input, inOutIdx, inSz) < 0)
            return ASN_DH_KEY_E;

        if (CheckBitString(input, inOutIdx, &length, inSz, 0, NULL) < 0)
            return ASN_PARSE_E;

        if (GetInt(&key->y,  input, inOutIdx, inSz) < 0 )
            return ASN_DH_KEY_E;

        ret = 0;
    }

    key->type = DSA_PUBLIC;
    return ret;
}

int wc_DsaPrivateKeyDecode(const byte* input, word32* inOutIdx, DsaKey* key,
                           word32 inSz)
{
    int length, version, ret = 0, temp = 0;
    word32 algId = 0;

    /* Sanity checks on input */
    if (input == NULL || inOutIdx == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

    /* if has pkcs8 header skip it */
    if (ToTraditionalInline_ex(input, inOutIdx, inSz, &algId) < 0) {
        /* ignore error, did not have pkcs8 header */
    }

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    temp = (int)*inOutIdx;

    /* Default case expects a certificate with OctetString but no version ID */
    ret = GetInt(&key->p, input, inOutIdx, inSz);
    if (ret < 0) {
        mp_clear(&key->p);
        ret = ASN_PARSE_E;
    }
    else {
        ret = GetInt(&key->q, input, inOutIdx, inSz);
        if (ret < 0) {
            mp_clear(&key->p);
            mp_clear(&key->q);
            ret = ASN_PARSE_E;
        }
        else {
            ret = GetInt(&key->g, input, inOutIdx, inSz);
            if (ret < 0) {
                mp_clear(&key->p);
                mp_clear(&key->q);
                mp_clear(&key->g);
                ret = ASN_PARSE_E;
            }
            else {
                ret = GetOctetString(input, inOutIdx, &length, inSz);
                if (ret < 0) {
                    mp_clear(&key->p);
                    mp_clear(&key->q);
                    mp_clear(&key->g);
                    ret = ASN_PARSE_E;
                }
                else {
                    ret = GetInt(&key->y, input, inOutIdx, inSz);
                    if (ret < 0) {
                        mp_clear(&key->p);
                        mp_clear(&key->q);
                        mp_clear(&key->g);
                        mp_clear(&key->y);
                        ret = ASN_PARSE_E;
                    }
                }
            }
        }
    }
    /* An alternate pass if default certificate fails parsing */
    if (ret == WC_NO_ERR_TRACE(ASN_PARSE_E)) {
        *inOutIdx = (word32)temp;
        if (GetMyVersion(input, inOutIdx, &version, inSz) < 0)
            return ASN_PARSE_E;

        if (GetInt(&key->p,  input, inOutIdx, inSz) < 0 ||
            GetInt(&key->q,  input, inOutIdx, inSz) < 0 ||
            GetInt(&key->g,  input, inOutIdx, inSz) < 0 ||
            GetInt(&key->y,  input, inOutIdx, inSz) < 0 ||
            GetInt(&key->x,  input, inOutIdx, inSz) < 0 )
            return ASN_DH_KEY_E;
    }

    key->type = DSA_PRIVATE;
    return 0;
}

/* Release Tmp DSA resources */
static WC_INLINE void FreeTmpDsas(byte** tmps, void* heap, int ints)
{
    int i;

    for (i = 0; i < ints; i++)
        XFREE(tmps[i], heap, DYNAMIC_TYPE_DSA);

    (void)heap;
}

#if !defined(HAVE_SELFTEST) && (defined(WOLFSSL_KEY_GEN) || \
defined(WOLFSSL_CERT_GEN))
int wc_SetDsaPublicKey(byte* output, DsaKey* key, int outLen, int with_header)
{
    /* p, g, q = DSA params, y = public exponent */
#ifdef WOLFSSL_SMALL_STACK
    byte* p = NULL;
    byte* g = NULL;
    byte* q = NULL;
    byte* y = NULL;
#else
    byte p[MAX_DSA_INT_SZ];
    byte g[MAX_DSA_INT_SZ];
    byte q[MAX_DSA_INT_SZ];
    byte y[MAX_DSA_INT_SZ];
#endif
    byte innerSeq[MAX_SEQ_SZ];
    byte outerSeq[MAX_SEQ_SZ];
    byte bitString[1 + MAX_LENGTH_SZ + 1];
    int pSz, gSz, qSz, ySz;
    word32 idx, innerSeqSz, outerSeqSz, bitStringSz = 0;
    WOLFSSL_ENTER("wc_SetDsaPublicKey");

    if (output == NULL || key == NULL || outLen < MAX_SEQ_SZ) {
        return BAD_FUNC_ARG;
    }

    /* p */
    WC_ALLOC_VAR_EX(p, byte, MAX_DSA_INT_SZ, key->heap,
        DYNAMIC_TYPE_TMP_BUFFER, return MEMORY_E);
    if ((pSz = SetASNIntMP(&key->p, MAX_DSA_INT_SZ, p)) < 0) {
        WOLFSSL_MSG("SetASNIntMP Error with p");
        WC_FREE_VAR_EX(p, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return pSz;
    }

    /* q */
    WC_ALLOC_VAR_EX(q, byte, MAX_DSA_INT_SZ, key->heap,
        DYNAMIC_TYPE_TMP_BUFFER, return MEMORY_E);
    if ((qSz = SetASNIntMP(&key->q, MAX_DSA_INT_SZ, q)) < 0) {
        WOLFSSL_MSG("SetASNIntMP Error with q");
        WC_FREE_VAR_EX(p, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        WC_FREE_VAR_EX(q, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return qSz;
    }

    /* g */
    WC_ALLOC_VAR_EX(g, byte, MAX_DSA_INT_SZ, key->heap,
        DYNAMIC_TYPE_TMP_BUFFER, return MEMORY_E);
    if ((gSz = SetASNIntMP(&key->g, MAX_DSA_INT_SZ, g)) < 0) {
        WOLFSSL_MSG("SetASNIntMP Error with g");
        WC_FREE_VAR_EX(p, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        WC_FREE_VAR_EX(q, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        WC_FREE_VAR_EX(g, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return gSz;
    }

    /* y */
    WC_ALLOC_VAR_EX(y, byte, MAX_DSA_INT_SZ, key->heap,
        DYNAMIC_TYPE_TMP_BUFFER, return MEMORY_E);
    if ((ySz = SetASNIntMP(&key->y, MAX_DSA_INT_SZ, y)) < 0) {
        WOLFSSL_MSG("SetASNIntMP Error with y");
        WC_FREE_VAR_EX(p, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        WC_FREE_VAR_EX(q, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        WC_FREE_VAR_EX(g, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        WC_FREE_VAR_EX(y, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ySz;
    }

    if (with_header) {
        word32 algoSz;
#ifdef WOLFSSL_SMALL_STACK
        byte* algo = NULL;

        algo = (byte*)XMALLOC(MAX_ALGO_SZ, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (algo == NULL) {
            XFREE(p,    key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(q,    key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(g,    key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(y,    key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
#else
        byte algo[MAX_ALGO_SZ];
#endif
        innerSeqSz  = SetSequence((word32)(pSz + qSz + gSz), innerSeq);
        algoSz = SetAlgoID(DSAk, algo, oidKeyType, 0);
        bitStringSz  = SetBitString((word32)ySz, 0, bitString);
        outerSeqSz = SetSequence(algoSz + innerSeqSz +
                                 (word32)(pSz + qSz + gSz), outerSeq);

        idx = SetSequence(algoSz + innerSeqSz + (word32)(pSz + qSz + gSz) +
                          bitStringSz + (word32)ySz + outerSeqSz, output);

        /* check output size */
        if ((idx + algoSz + bitStringSz + innerSeqSz +
             (word32)(pSz + qSz + gSz + ySz)) > (word32)outLen)
        {
                WC_FREE_VAR_EX(p, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
                WC_FREE_VAR_EX(q, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
                WC_FREE_VAR_EX(g, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
                WC_FREE_VAR_EX(y, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
                WC_FREE_VAR_EX(algo, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            WOLFSSL_MSG("Error, output size smaller than outlen");
            return BUFFER_E;
        }

        /* outerSeq */
        XMEMCPY(output + idx, outerSeq, outerSeqSz);
        idx += outerSeqSz;
        /* algo */
        XMEMCPY(output + idx, algo, algoSz);
        idx += algoSz;
        WC_FREE_VAR_EX(algo, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    } else {
        innerSeqSz  = SetSequence((word32)(pSz + qSz + gSz + ySz), innerSeq);

        /* check output size */
        if ((innerSeqSz + (word32)(pSz + qSz + gSz + ySz)) > (word32)outLen) {
            WC_FREE_VAR_EX(p, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            WC_FREE_VAR_EX(q, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            WC_FREE_VAR_EX(g, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            WC_FREE_VAR_EX(y, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            WOLFSSL_MSG("Error, output size smaller than outlen");
            return BUFFER_E;
        }

        idx = 0;
    }

    /* innerSeq */
    XMEMCPY(output + idx, innerSeq, innerSeqSz);
    idx += innerSeqSz;
    /* p */
    XMEMCPY(output + idx, p, (size_t)pSz);
    idx += (word32)pSz;
    /* q */
    XMEMCPY(output + idx, q, (size_t)qSz);
    idx += (word32)qSz;
    /* g */
    XMEMCPY(output + idx, g, (size_t)gSz);
    idx += (word32)gSz;
    /* bit string */
    if (bitStringSz > 0) {
        XMEMCPY(output + idx, bitString, bitStringSz);
        idx += bitStringSz;
    }
    /* y */
    XMEMCPY(output + idx, y, (size_t)ySz);
    idx += (word32)ySz;

    WC_FREE_VAR_EX(p, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    WC_FREE_VAR_EX(q, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    WC_FREE_VAR_EX(g, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    WC_FREE_VAR_EX(y, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return (int)idx;
}

#endif
static int DsaKeyIntsToDer(DsaKey* key, byte* output, word32* inLen,
                           int ints, int includeVersion)
{
    word32 seqSz = 0, verSz = 0, intTotalLen = 0, outLen, j;
    word32 sizes[DSA_INTS];
    int    i, ret = 0;

    byte  seq[MAX_SEQ_SZ];
    byte  ver[MAX_VERSION_SZ];
    byte* tmps[DSA_INTS];

    if (ints > DSA_INTS || inLen == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sizes, 0, sizeof(sizes));
    for (i = 0; i < ints; i++)
        tmps[i] = NULL;

    /* write all big ints from key to DER tmps */
    for (i = 0; i < ints; i++) {
        int mpSz;
        mp_int* keyInt = GetDsaInt(key, i);
        word32 rawLen = (word32)mp_unsigned_bin_size(keyInt) + 1;

        tmps[i] = (byte*)XMALLOC(rawLen + MAX_SEQ_SZ, key->heap,
                                                              DYNAMIC_TYPE_DSA);
        if (tmps[i] == NULL) {
            ret = MEMORY_E;
            break;
        }

        mpSz = SetASNIntMP(keyInt, -1, tmps[i]);
        if (mpSz < 0) {
            ret = mpSz;
            break;
        }
        sizes[i] = (word32)mpSz;
        intTotalLen += (word32)mpSz;
    }

    if (ret != 0) {
        FreeTmpDsas(tmps, key->heap, ints);
        return ret;
    }

    /* make headers */
    if (includeVersion)
        verSz = (word32)SetMyVersion(0, ver, FALSE);
    seqSz = SetSequence(verSz + intTotalLen, seq);

    outLen = seqSz + verSz + intTotalLen;
    if (output == NULL) {
        *inLen = outLen;
        FreeTmpDsas(tmps, key->heap, ints);
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }
    if (outLen > *inLen) {
        FreeTmpDsas(tmps, key->heap, ints);
        return BAD_FUNC_ARG;
    }
    *inLen = outLen;

    /* write to output */
    XMEMCPY(output, seq, seqSz);
    j = seqSz;
    if (includeVersion) {
        XMEMCPY(output + j, ver, verSz);
        j += verSz;
    }

    for (i = 0; i < ints; i++) {
        XMEMCPY(output + j, tmps[i], sizes[i]);
        j += sizes[i];
    }
    FreeTmpDsas(tmps, key->heap, ints);

    return (int)outLen;
}

#endif
#ifndef NO_CERTS
static int GetCertHeader(DecodedCert* cert)
{
    int ret = 0, len;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    /* Reset the max index for the size indicated in the outer wrapper. */
    cert->maxIdx = (word32)len + cert->srcIdx;
    cert->certBegin = cert->srcIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &len, cert->maxIdx) < 0)
        return ASN_PARSE_E;

    cert->sigIndex = (word32)len + cert->srcIdx;
    if (cert->sigIndex > cert->maxIdx)
        return ASN_PARSE_E;

    if (GetExplicitVersion(cert->source, &cert->srcIdx, &cert->version,
                                                            cert->sigIndex) < 0)
        return ASN_PARSE_E;

    ret = wc_GetSerialNumber(cert->source, &cert->srcIdx, cert->serial,
        &cert->serialSz, cert->sigIndex);
    if (ret < 0) {
        return ret;
    }

    return ret;
}

#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)
static int SetEccPublicKey(byte* output, ecc_key* key, int outLen,
                           int with_header, int comp)
{
    int ret;
    word32 idx = 0, curveSz, algoSz, pubSz, bitStringSz;
    byte bitString[1 + MAX_LENGTH_SZ + 1]; /* 6 */
    byte algo[MAX_ALGO_SZ];  /* 20 */

    /* public size */
    pubSz = key->dp ? (word32)key->dp->size : MAX_ECC_BYTES;
    if (comp)
        pubSz = 1 + pubSz;
    else
        pubSz = 1 + 2 * pubSz;

    /* check for buffer overflow */
    if (output != NULL && pubSz > (word32)outLen) {
        return BUFFER_E;
    }

    /* headers */
    if (with_header) {
        ret = SetCurve(key, NULL, 0);
        if (ret <= 0) {
            return ret;
        }
        curveSz = (word32)ret;
        ret = 0;

        /* calculate size */
        algoSz  = SetAlgoID(ECDSAk, algo, oidKeyType, (int)curveSz);
        bitStringSz = SetBitString(pubSz, 0, bitString);
        idx = SetSequence(pubSz + curveSz + bitStringSz + algoSz, NULL);

        /* check for buffer overflow */
        if (output != NULL &&
                curveSz + algoSz + bitStringSz + idx + pubSz > (word32)outLen) {
            return BUFFER_E;
        }

        idx = SetSequence(pubSz + curveSz + bitStringSz + algoSz,
            output);
        /* algo */
        if (output)
            XMEMCPY(output + idx, algo, algoSz);
        idx += algoSz;
        /* curve */
        if (output)
            (void)SetCurve(key, output + idx, curveSz);
        idx += curveSz;
        /* bit string */
        if (output)
            XMEMCPY(output + idx, bitString, bitStringSz);
        idx += bitStringSz;
    }

    /* pub */
    if (output) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963_ex(key, output + idx, &pubSz, comp);
        PRIVATE_KEY_LOCK();
        if (ret != 0) {
            return ret;
        }
    }
    idx += pubSz;

    return (int)idx;
}

#endif
#ifdef WC_ENABLE_ASYM_KEY_EXPORT
int SetAsymKeyDerPublic(const byte* pubKey, word32 pubKeyLen,
    byte* output, word32 outLen, int keyType, int withHeader)
{
    int ret = 0;
    word32 idx = 0;
    word32 seqDataSz = 0;
    word32 sz;

    /* validate parameters */
    if (pubKey == NULL){
        return BAD_FUNC_ARG;
    }
    if (output != NULL && outLen == 0) {
        return BUFFER_E;
    }

    /* calculate size */
    if (withHeader) {
        word32 algoSz      = SetAlgoID(keyType, NULL, oidKeyType, 0);
        word32 bitStringSz = SetBitString(pubKeyLen, 0, NULL);

        seqDataSz = algoSz + bitStringSz + pubKeyLen;
        sz = SetSequence(seqDataSz, NULL) + seqDataSz;
    }
    else {
        sz = pubKeyLen;
    }

    /* checkout output size */
    if (output != NULL && sz > outLen) {
        ret = BUFFER_E;
    }

    /* headers */
    if (ret == 0 && output != NULL && withHeader) {
        /* sequence */
        idx = SetSequence(seqDataSz, output);
        /* algo */
        idx += SetAlgoID(keyType, output + idx, oidKeyType, 0);
        /* bit string */
        idx += SetBitString(pubKeyLen, 0, output + idx);
    }

    if (ret == 0 && output != NULL) {
        /* pub */
        XMEMCPY(output + idx, pubKey, pubKeyLen);
        idx += pubKeyLen;

        sz = idx;
    }

    if (ret == 0) {
        ret = (int)sz;
    }
    return ret;
}

#endif
#if !defined(NO_RSA) && !defined(NO_CERTS)
static int StoreRsaKey(DecodedCert* cert, const byte* source, word32* srcIdx,
                       word32 maxIdx)
{
    int    length;
    int    pubLen;
    word32 pubIdx;

    if (CheckBitString(source, srcIdx, &pubLen, maxIdx, 1, NULL) != 0)
        return ASN_PARSE_E;
    pubIdx = *srcIdx;

    if (GetSequence(source, srcIdx, &length, pubIdx + (word32)pubLen) < 0)
        return ASN_PARSE_E;

#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_FSPSM_TLS)
    cert->sigCtx.CertAtt.pubkey_n_start =
            cert->sigCtx.CertAtt.pubkey_e_start = pubIdx;
#endif
    cert->pubKeySize = (word32)pubLen;
    cert->publicKey = source + pubIdx;
#ifdef WOLFSSL_MAXQ10XX_TLS
    cert->publicKeyIndex = pubIdx;
#endif
    *srcIdx += (word32)length;

#ifdef HAVE_OCSP
    return CalcHashId_ex(cert->publicKey, cert->pubKeySize,
        cert->subjectKeyHash, HashIdAlg(cert->signatureOID));
#else
    return 0;
#endif
}

#endif
#if defined(HAVE_ECC) && !defined(NO_CERTS)
static int StoreEccKey(DecodedCert* cert, const byte* source, word32* srcIdx,
                       word32 maxIdx, const byte* pubKey, word32 pubKeyLen)
{
    int ret;
    word32 localIdx;
    byte* publicKey;
    byte  tag;
    int length;

    if (pubKey == NULL) {
        return BAD_FUNC_ARG;
    }

    localIdx = *srcIdx;
    if (GetASNTag(source, &localIdx, &tag, maxIdx) < 0)
        return ASN_PARSE_E;

    if (tag != (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
        if (GetObjectId(source, srcIdx, &cert->pkCurveOID, oidCurveType,
                                                                    maxIdx) < 0)
            return ASN_PARSE_E;

        if ((ret = CheckCurve(cert->pkCurveOID)) < 0)
            return ECC_CURVE_OID_E;

    #if defined(WOLFSSL_RENESAS_FSPSM_TLS) || defined(WOLFSSL_RENESAS_TSIP_TLS)
        cert->sigCtx.CertAtt.curve_id = ret;
    #else
        (void)ret;
    #endif
        /* key header */
        ret = CheckBitString(source, srcIdx, &length, maxIdx, 1, NULL);
        if (ret != 0)
            return ret;
    #if defined(WOLFSSL_RENESAS_FSPSM_TLS) || defined(WOLFSSL_RENESAS_TSIP_TLS)
        cert->sigCtx.CertAtt.pubkey_n_start =
                cert->sigCtx.CertAtt.pubkey_e_start = (*srcIdx + 1);
        cert->sigCtx.CertAtt.pubkey_n_len = ((length - 1) >> 1);
        cert->sigCtx.CertAtt.pubkey_e_start +=
                cert->sigCtx.CertAtt.pubkey_n_len;
        cert->sigCtx.CertAtt.pubkey_e_len   =
                cert->sigCtx.CertAtt.pubkey_n_len;
    #endif
    #ifdef WOLFSSL_MAXQ10XX_TLS
        cert->publicKeyIndex = *srcIdx + 1;
    #endif

    #ifdef HAVE_OCSP
        ret = CalcHashId_ex(source + *srcIdx, (word32)length,
            cert->subjectKeyHash, HashIdAlg(cert->signatureOID));
        if (ret != 0)
            return ret;
    #endif
        *srcIdx += (word32)length;
    }

    publicKey = (byte*)XMALLOC(pubKeyLen, cert->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (publicKey == NULL)
        return MEMORY_E;
    XMEMCPY(publicKey, pubKey, pubKeyLen);
    cert->publicKey = publicKey;
    cert->pubKeyStored = 1;
    cert->pubKeySize   = pubKeyLen;

    return 0;
}

#endif
#ifndef NO_CERTS
#if !defined(NO_DSA)
static int ParseDsaKey(const byte* source, word32* srcIdx, word32 maxIdx,
                       void* heap)
{
    int ret;
    int length;

    (void)heap;

    ret = GetSequence(source, srcIdx, &length, maxIdx);
    if (ret < 0)
        return ret;

    ret = SkipInt(source, srcIdx, maxIdx);
    if (ret != 0)
        return ret;
    ret = SkipInt(source, srcIdx, maxIdx);
    if (ret != 0)
        return ret;
    ret = SkipInt(source, srcIdx, maxIdx);
    if (ret != 0)
        return ret;

    ret = CheckBitString(source, srcIdx, &length, maxIdx, 1, NULL);
    if (ret != 0)
        return ret;

    ret = GetASNInt(source, srcIdx, &length, maxIdx);
    if (ret != 0)
        return ASN_PARSE_E;

    *srcIdx += (word32)length;

    return 0;
}

#endif
#endif
static int GetCertName(DecodedCert* cert, char* full, byte* hash, int nameType,
                       const byte* input, word32* inOutIdx, word32 maxIdx)
{
    int    length;  /* length of all distinguished names */
    int    dummy;
    int    ret;
    word32 idx;
    word32 srcIdx = *inOutIdx;
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    !defined(WOLFCRYPT_ONLY)
    WOLFSSL_X509_NAME* dName = NULL;
#endif

    WOLFSSL_MSG("Getting Cert Name");

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    if (CalcHashId_ex(input + *inOutIdx, maxIdx - *inOutIdx, hash,
            HashIdAlg(cert->signatureOID)) != 0) {
        return ASN_PARSE_E;
    }

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    !defined(WOLFCRYPT_ONLY)
    dName = wolfSSL_X509_NAME_new_ex(cert->heap);
    if (dName == NULL) {
        return MEMORY_E;
    }
#endif /* OPENSSL_EXTRA */

    if (GetSequence(input, &srcIdx, &length, maxIdx) < 0) {
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
            !defined(WOLFCRYPT_ONLY)
        wolfSSL_X509_NAME_free(dName);
#endif /* OPENSSL_EXTRA */
        return ASN_PARSE_E;
    }

#if defined(HAVE_PKCS7) || defined(WOLFSSL_CERT_EXT)
    /* store pointer to raw issuer */
    if (nameType == ASN_ISSUER) {
        cert->issuerRaw = &input[srcIdx];
        cert->issuerRawLen = length;
    }
#endif
#if !defined(IGNORE_NAME_CONSTRAINTS) || defined(WOLFSSL_CERT_EXT)
    if (nameType == ASN_SUBJECT) {
        cert->subjectRaw = &input[srcIdx];
        cert->subjectRawLen = length;
    }
#endif

    length += (int)srcIdx;
    idx = 0;

    while (srcIdx < (word32)length) {
        byte        b       = 0;
        byte        joint[3];
        byte        tooBig  = FALSE;
        int         oidSz;
        const char* copy    = NULL;
        int         copyLen = 0;
        int         strLen  = 0;
        byte        id      = 0;
    #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) \
                && !defined(WOLFCRYPT_ONLY)
         int        nid = WC_NID_undef;
         int        enc;
    #endif /* OPENSSL_EXTRA */

        if (GetSet(input, &srcIdx, &dummy, maxIdx) < 0) {
            WOLFSSL_MSG("Cert name lacks set header, trying sequence");
        }

        if (GetSequence(input, &srcIdx, &dummy, maxIdx) <= 0) {
        #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
            !defined(WOLFCRYPT_ONLY)
            wolfSSL_X509_NAME_free(dName);
        #endif /* OPENSSL_EXTRA */
            return ASN_PARSE_E;
        }

        ret = GetASNObjectId(input, &srcIdx, &oidSz, maxIdx);
        if (ret != 0) {
        #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
            !defined(WOLFCRYPT_ONLY)
            wolfSSL_X509_NAME_free(dName);
        #endif /* OPENSSL_EXTRA */
            return ret;
        }

        /* make sure there is room for joint */
        if ((srcIdx + sizeof(joint)) > (word32)maxIdx) {
        #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
            !defined(WOLFCRYPT_ONLY)
            wolfSSL_X509_NAME_free(dName);
        #endif /* OPENSSL_EXTRA */
            return ASN_PARSE_E;
        }

        XMEMCPY(joint, &input[srcIdx], sizeof(joint));

        /* v1 name types */
        if (joint[0] == 0x55 && joint[1] == 0x04) {
            srcIdx += 3;
            id = joint[2];
            if (GetHeader(input, &b, &srcIdx, &strLen, maxIdx, 1) < 0) {
            #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
            !defined(WOLFCRYPT_ONLY)
                wolfSSL_X509_NAME_free(dName);
            #endif /* OPENSSL_EXTRA */
                return ASN_PARSE_E;
            }

        #ifndef WOLFSSL_NO_ASN_STRICT
            /* RFC 5280 section 4.1.2.4 lists a DirectoryString as being
             * 1..MAX in length */
            if (strLen < 1) {
                WOLFSSL_MSG("Non conforming DirectoryString of length 0 was"
                            " found");
                WOLFSSL_MSG("Use WOLFSSL_NO_ASN_STRICT if wanting to allow"
                            " empty DirectoryString's");
            #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
            !defined(WOLFCRYPT_ONLY)
                wolfSSL_X509_NAME_free(dName);
            #endif /* OPENSSL_EXTRA */
                return ASN_PARSE_E;
            }
        #endif

            if (id == ASN_COMMON_NAME) {
                if (nameType == ASN_SUBJECT) {
                    cert->subjectCN = (char *)&input[srcIdx];
                    cert->subjectCNLen = strLen;
                    cert->subjectCNEnc = (char)b;
                }
            #if (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)) && \
                defined(WOLFSSL_HAVE_ISSUER_NAMES)
                else if (nameType == ASN_ISSUER) {
                    cert->issuerCN = (char*)&input[srcIdx];
                    cert->issuerCNLen = strLen;
                    cert->issuerCNEnc = (char)b;
                }
            #endif

                copy = WOLFSSL_COMMON_NAME;
                copyLen = sizeof(WOLFSSL_COMMON_NAME) - 1;
            #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) \
                && !defined(WOLFCRYPT_ONLY)
                nid = WC_NID_commonName;
            #endif /* OPENSSL_EXTRA */
            }
        #ifdef WOLFSSL_CERT_NAME_ALL
            else if (id == ASN_NAME) {
                copy = WOLFSSL_NAME;
                copyLen = sizeof(WOLFSSL_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectN = (char*)&input[srcIdx];
                        cert->subjectNLen = strLen;
                        cert->subjectNEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_name;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_INITIALS) {
                copy = WOLFSSL_INITIALS;
                copyLen = sizeof(WOLFSSL_INITIALS) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectI = (char*)&input[srcIdx];
                        cert->subjectILen = strLen;
                        cert->subjectIEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_initials;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_GIVEN_NAME) {
                copy = WOLFSSL_GIVEN_NAME;
                copyLen = sizeof(WOLFSSL_GIVEN_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectGN = (char*)&input[srcIdx];
                        cert->subjectGNLen = strLen;
                        cert->subjectGNEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_givenName;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_DNQUALIFIER) {
                copy = WOLFSSL_DNQUALIFIER;
                copyLen = sizeof(WOLFSSL_DNQUALIFIER) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectDNQ = (char*)&input[srcIdx];
                        cert->subjectDNQLen = strLen;
                        cert->subjectDNQEnc = b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_dnQualifier;
                #endif /* OPENSSL_EXTRA */
            }
        #endif /* WOLFSSL_CERT_NAME_ALL */
            else if (id == ASN_SUR_NAME) {
                copy = WOLFSSL_SUR_NAME;
                copyLen = sizeof(WOLFSSL_SUR_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectSN = (char*)&input[srcIdx];
                        cert->subjectSNLen = strLen;
                        cert->subjectSNEnc = (char)b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ASN_ISSUER) {
                        cert->issuerSN = (char*)&input[srcIdx];
                        cert->issuerSNLen = strLen;
                        cert->issuerSNEnc = (char)b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_surname;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_COUNTRY_NAME) {
                copy = WOLFSSL_COUNTRY_NAME;
                copyLen = sizeof(WOLFSSL_COUNTRY_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectC = (char*)&input[srcIdx];
                        cert->subjectCLen = strLen;
                        cert->subjectCEnc = (char)b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ASN_ISSUER) {
                        cert->issuerC = (char*)&input[srcIdx];
                        cert->issuerCLen = strLen;
                        cert->issuerCEnc = (char)b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_countryName;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_LOCALITY_NAME) {
                copy = WOLFSSL_LOCALITY_NAME;
                copyLen = sizeof(WOLFSSL_LOCALITY_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectL = (char*)&input[srcIdx];
                        cert->subjectLLen = strLen;
                        cert->subjectLEnc = (char)b;
                    }
                    #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ASN_ISSUER) {
                        cert->issuerL = (char*)&input[srcIdx];
                        cert->issuerLLen = strLen;
                        cert->issuerLEnc = (char)b;
                    }
                    #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_localityName;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_STATE_NAME) {
                copy = WOLFSSL_STATE_NAME;
                copyLen = sizeof(WOLFSSL_STATE_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectST = (char*)&input[srcIdx];
                        cert->subjectSTLen = strLen;
                        cert->subjectSTEnc = (char)b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ASN_ISSUER) {
                        cert->issuerST = (char*)&input[srcIdx];
                        cert->issuerSTLen = strLen;
                        cert->issuerSTEnc = (char)b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT*/
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_stateOrProvinceName;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_ORG_NAME) {
                copy = WOLFSSL_ORG_NAME;
                copyLen = sizeof(WOLFSSL_ORG_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectO = (char*)&input[srcIdx];
                        cert->subjectOLen = strLen;
                        cert->subjectOEnc = (char)b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ASN_ISSUER) {
                        cert->issuerO = (char*)&input[srcIdx];
                        cert->issuerOLen = strLen;
                        cert->issuerOEnc = (char)b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_organizationName;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_ORGUNIT_NAME) {
                copy = WOLFSSL_ORGUNIT_NAME;
                copyLen = sizeof(WOLFSSL_ORGUNIT_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectOU = (char*)&input[srcIdx];
                        cert->subjectOULen = strLen;
                        cert->subjectOUEnc = (char)b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ASN_ISSUER) {
                        cert->issuerOU = (char*)&input[srcIdx];
                        cert->issuerOULen = strLen;
                        cert->issuerOUEnc = (char)b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_organizationalUnitName;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_SERIAL_NUMBER) {
                copy = WOLFSSL_SERIAL_NUMBER;
                copyLen = sizeof(WOLFSSL_SERIAL_NUMBER) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectSND = (char*)&input[srcIdx];
                        cert->subjectSNDLen = strLen;
                        cert->subjectSNDEnc = (char)b;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES)
                    else if (nameType == ASN_ISSUER) {
                        cert->issuerSND = (char*)&input[srcIdx];
                        cert->issuerSNDLen = strLen;
                        cert->issuerSNDEnc = (char)b;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_serialNumber;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_USER_ID) {
                copy = WOLFSSL_USER_ID;
                copyLen = sizeof(WOLFSSL_USER_ID) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectUID = (char*)&input[srcIdx];
                        cert->subjectUIDLen = strLen;
                        cert->subjectUIDEnc = (char)b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_userId;
                #endif /* OPENSSL_EXTRA */
            }
        #ifdef WOLFSSL_CERT_EXT
            else if (id == ASN_STREET_ADDR) {
                copy = WOLFSSL_STREET_ADDR_NAME;
                copyLen = sizeof(WOLFSSL_STREET_ADDR_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectStreet = (char*)&input[srcIdx];
                        cert->subjectStreetLen = strLen;
                        cert->subjectStreetEnc = (char)b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_streetAddress;
                #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_BUS_CAT) {
                copy = WOLFSSL_BUS_CAT;
                copyLen = sizeof(WOLFSSL_BUS_CAT) - 1;
            #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                if (nameType == ASN_SUBJECT) {
                    cert->subjectBC = (char*)&input[srcIdx];
                    cert->subjectBCLen = strLen;
                    cert->subjectBCEnc = (char)b;
                }
            #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
            #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                nid = WC_NID_businessCategory;
            #endif /* OPENSSL_EXTRA */
            }
            else if (id == ASN_POSTAL_CODE) {
                copy = WOLFSSL_POSTAL_NAME;
                copyLen = sizeof(WOLFSSL_POSTAL_NAME) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectPC = (char*)&input[srcIdx];
                        cert->subjectPCLen = strLen;
                        cert->subjectPCEnc = (char)b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT*/
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_postalCode;
                #endif /* OPENSSL_EXTRA */
            }
        #endif /* WOLFSSL_CERT_EXT */
        }
    #ifdef WOLFSSL_CERT_EXT
        else if ((srcIdx + ASN_JOI_PREFIX_SZ + 2 <= (word32)maxIdx) &&
                 (0 == XMEMCMP(&input[srcIdx], ASN_JOI_PREFIX,
                               ASN_JOI_PREFIX_SZ)) &&
                 ((input[srcIdx+ASN_JOI_PREFIX_SZ] == ASN_JOI_C) ||
                  (input[srcIdx+ASN_JOI_PREFIX_SZ] == ASN_JOI_ST)))
        {
            srcIdx += ASN_JOI_PREFIX_SZ;
            id = input[srcIdx++];
            b = input[srcIdx++]; /* encoding */

            if (GetLength(input, &srcIdx, &strLen,
                          maxIdx) < 0) {
            #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
            !defined(WOLFCRYPT_ONLY)
                wolfSSL_X509_NAME_free(dName);
            #endif /* OPENSSL_EXTRA */
                return ASN_PARSE_E;
            }

            /* Check for jurisdiction of incorporation country name */
            if (id == ASN_JOI_C) {
                copy = WOLFSSL_JOI_C;
                copyLen = sizeof(WOLFSSL_JOI_C) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectJC = (char*)&input[srcIdx];
                        cert->subjectJCLen = strLen;
                        cert->subjectJCEnc = (char)b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_jurisdictionCountryName;
                #endif /* OPENSSL_EXTRA */
            }

            /* Check for jurisdiction of incorporation state name */
            else if (id == ASN_JOI_ST) {
                copy = WOLFSSL_JOI_ST;
                copyLen = sizeof(WOLFSSL_JOI_ST) - 1;
                #if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectJS = (char*)&input[srcIdx];
                        cert->subjectJSLen = strLen;
                        cert->subjectJSEnc = (char)b;
                    }
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_jurisdictionStateOrProvinceName;
                #endif /* OPENSSL_EXTRA */
            }

            if ((strLen + copyLen) > (int)(WC_ASN_NAME_MAX - idx)) {
                WOLFSSL_MSG("ASN Name too big, skipping");
                tooBig = TRUE;
            }
        }
    #endif /* WOLFSSL_CERT_EXT */
        else {
            /* skip */
            byte email = FALSE;
            byte pilot = FALSE;

            if (joint[0] == 0x2a && joint[1] == 0x86) {  /* email id hdr 42.134.* */
                id = ASN_EMAIL_NAME;
                email = TRUE;
            }

            if (joint[0] == 0x9  && joint[1] == 0x92) { /* uid id hdr 9.146.* */
                /* last value of OID is the type of pilot attribute */
                id    = input[srcIdx + (word32)oidSz - 1];
                if (id == 0x01)
                    id = ASN_USER_ID;
                pilot = TRUE;
            }

            srcIdx += (word32)oidSz + 1;

            if (GetLength(input, &srcIdx, &strLen, maxIdx) < 0) {
            #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
            !defined(WOLFCRYPT_ONLY)
                wolfSSL_X509_NAME_free(dName);
            #endif /* OPENSSL_EXTRA */
                return ASN_PARSE_E;
            }

            if (strLen > (int)(WC_ASN_NAME_MAX - idx)) {
                WOLFSSL_MSG("ASN name too big, skipping");
                tooBig = TRUE;
            }

            if (email) {
                copyLen = sizeof(WOLFSSL_EMAIL_ADDR) - 1;
                if ((copyLen + strLen) > (int)(WC_ASN_NAME_MAX - idx)) {
                    WOLFSSL_MSG("ASN name too big, skipping");
                    tooBig = TRUE;
                }
                else {
                    copy = WOLFSSL_EMAIL_ADDR;
                }

                #if !defined(IGNORE_NAME_CONSTRAINTS) || \
                     defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT)
                    if (nameType == ASN_SUBJECT) {
                        cert->subjectEmail = (char*)&input[srcIdx];
                        cert->subjectEmailLen = strLen;
                    }
                #if defined(WOLFSSL_HAVE_ISSUER_NAMES) && \
                    (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_EXT))
                    else if (nameType == ASN_ISSUER) {
                        cert->issuerEmail = (char*)&input[srcIdx];
                        cert->issuerEmailLen = strLen;
                    }
                #endif /* WOLFSSL_HAVE_ISSUER_NAMES */
                #endif /* WOLFSSL_CERT_GEN || WOLFSSL_CERT_EXT */
                #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                    nid = WC_NID_emailAddress;
                #endif /* OPENSSL_EXTRA */
            }

            if (pilot) {
                switch (id) {
                    case ASN_USER_ID:
                        copy = WOLFSSL_USER_ID;
                        copyLen = sizeof(WOLFSSL_USER_ID) - 1;
                    #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                        nid = WC_NID_userId;
                    #endif /* OPENSSL_EXTRA */
                        break;
                    case ASN_DOMAIN_COMPONENT:
                        copy = WOLFSSL_DOMAIN_COMPONENT;
                        copyLen = sizeof(WOLFSSL_DOMAIN_COMPONENT) - 1;
                    #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                        nid = WC_NID_domainComponent;
                    #endif /* OPENSSL_EXTRA */
                        break;
                    case ASN_RFC822_MAILBOX:
                        copy = WOLFSSL_RFC822_MAILBOX;
                        copyLen = sizeof(WOLFSSL_RFC822_MAILBOX) - 1;
                    #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                        nid = WC_NID_rfc822Mailbox;
                    #endif /* OPENSSL_EXTRA */
                        break;
                    case ASN_FAVOURITE_DRINK:
                        copy = WOLFSSL_FAVOURITE_DRINK;
                        copyLen = sizeof(WOLFSSL_FAVOURITE_DRINK) - 1;
                    #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                        nid = WC_NID_favouriteDrink;
                    #endif /* OPENSSL_EXTRA */
                        break;
                    case ASN_CONTENT_TYPE:
                        copy = WOLFSSL_CONTENT_TYPE;
                        copyLen = sizeof(WOLFSSL_CONTENT_TYPE) - 1;
                    #if (defined(OPENSSL_EXTRA) || \
                        defined(OPENSSL_EXTRA_X509_SMALL)) \
                        && !defined(WOLFCRYPT_ONLY)
                        nid = WC_NID_pkcs9_contentType;
                    #endif /* OPENSSL_EXTRA */
                        break;
                    default:
                        WOLFSSL_MSG("Unknown pilot attribute type");
                    #if (defined(OPENSSL_EXTRA) || \
                                defined(OPENSSL_EXTRA_X509_SMALL)) && \
                                !defined(WOLFCRYPT_ONLY)
                        wolfSSL_X509_NAME_free(dName);
                    #endif /* OPENSSL_EXTRA */
                        return ASN_PARSE_E;
                }
            }
        }
        if ((copyLen + strLen) > (int)(WC_ASN_NAME_MAX - idx))
        {
            WOLFSSL_MSG("ASN Name too big, skipping");
            tooBig = TRUE;
        }
        if ((copy != NULL) && !tooBig) {
            XMEMCPY(&full[idx], copy, (size_t)copyLen);
            idx += (word32)copyLen;
            XMEMCPY(&full[idx], &input[srcIdx], (size_t)strLen);
            idx += (word32)strLen;
        }
        #if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
            !defined(WOLFCRYPT_ONLY)
        switch (b) {
            case CTC_UTF8:
                enc = WOLFSSL_MBSTRING_UTF8;
                break;
            case CTC_PRINTABLE:
                enc = WOLFSSL_V_ASN1_PRINTABLESTRING;
                break;
            default:
                WOLFSSL_MSG("Unknown encoding type, using UTF8 by default");
                enc = WOLFSSL_MBSTRING_UTF8;
        }

        if (nid != WC_NID_undef) {
            if (wolfSSL_X509_NAME_add_entry_by_NID(dName, nid, enc,
                            &input[srcIdx], strLen, -1, -1) !=
                            WOLFSSL_SUCCESS) {
                wolfSSL_X509_NAME_free(dName);
                return ASN_PARSE_E;
            }
        }
        #endif /* OPENSSL_EXTRA */
        srcIdx += (word32)strLen;
    }
    full[idx++] = 0;

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
            !defined(WOLFCRYPT_ONLY)
    if (nameType == ASN_ISSUER) {
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)) &&\
    (defined(HAVE_PKCS7) || defined(WOLFSSL_CERT_EXT))
        dName->rawLen = min(cert->issuerRawLen, WC_ASN_NAME_MAX);
        XMEMCPY(dName->raw, cert->issuerRaw, dName->rawLen);
#endif
        cert->issuerName = dName;
    }
    else {
#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX)
        dName->rawLen = min(cert->subjectRawLen, WC_ASN_NAME_MAX);
        XMEMCPY(dName->raw, cert->subjectRaw, dName->rawLen);
#endif
        cert->subjectName = dName;
    }
#endif

    *inOutIdx = srcIdx;

    return 0;
}

int GetName(DecodedCert* cert, int nameType, int maxIdx)
{
    char*  full;
    byte*  hash;
    int    length;
    word32 localIdx;
    byte   tag;

    WOLFSSL_MSG("Getting Name");

    if (nameType == ASN_ISSUER) {
        full = cert->issuer;
        hash = cert->issuerHash;
    }
    else {
        full = cert->subject;
        hash = cert->subjectHash;
    }

    if (cert->srcIdx >= (word32)maxIdx) {
        return BUFFER_E;
    }

    localIdx = cert->srcIdx;
    if (GetASNTag(cert->source, &localIdx, &tag, (word32)maxIdx) < 0) {
        return ASN_PARSE_E;
    }

    if (tag == ASN_OBJECT_ID) {
        WOLFSSL_MSG("Trying optional prefix...");

        if (SkipObjectId(cert->source, &cert->srcIdx, (word32)maxIdx) < 0)
            return ASN_PARSE_E;
        WOLFSSL_MSG("Got optional prefix");
    }

    localIdx = cert->srcIdx;
    if (GetASNTag(cert->source, &localIdx, &tag, (word32)maxIdx) < 0) {
        return ASN_PARSE_E;
    }
    localIdx = cert->srcIdx + 1;
    if (GetLength(cert->source, &localIdx, &length, (word32)maxIdx) < 0) {
        return ASN_PARSE_E;
    }
    length += (int)(localIdx - cert->srcIdx);

    return GetCertName(cert, full, hash, nameType, cert->source, &cert->srcIdx,
                       cert->srcIdx + (word32)length);
}

static int GetDateInfo(const byte* source, word32* idx, const byte** pDate,
                        byte* pFormat, int* pLength, word32 maxIdx)
{
    int length;
    byte format;

    if (source == NULL || idx == NULL)
        return BAD_FUNC_ARG;

    /* get ASN format header */
    if (*idx+1 > maxIdx)
        return BUFFER_E;
    format = source[*idx];
    *idx += 1;
    if (format != ASN_UTC_TIME && format != ASN_GENERALIZED_TIME) {
        WOLFSSL_ERROR_VERBOSE(ASN_TIME_E);
        return ASN_TIME_E;
    }

    /* get length */
    if (GetLength(source, idx, &length, maxIdx) < 0)
        return ASN_PARSE_E;
    if (length > MAX_DATE_SIZE || length < MIN_DATE_SIZE)
        return ASN_DATE_SZ_E;

    /* return format, date and length */
    if (pFormat)
        *pFormat = format;
    if (pDate)
        *pDate = &source[*idx];
    if (pLength)
        *pLength = length;

    *idx += (word32)length;

    return 0;
}

#ifndef NO_CERTS
static int GetDate(DecodedCert* cert, int dateType, int verify, int maxIdx)
{
    int    ret, length;
    const byte *datePtr = NULL;
    byte   date[MAX_DATE_SIZE];
    byte   format;
    word32 startIdx = 0;

    if (dateType == ASN_BEFORE)
        cert->beforeDate = &cert->source[cert->srcIdx];
    else
        cert->afterDate = &cert->source[cert->srcIdx];
    startIdx = cert->srcIdx;

    ret = GetDateInfo(cert->source, &cert->srcIdx, &datePtr, &format,
                      &length, (word32)maxIdx);
    if (ret < 0)
        return ret;

    XMEMSET(date, 0, MAX_DATE_SIZE);
    XMEMCPY(date, datePtr, (size_t)length);

    if (dateType == ASN_BEFORE)
        cert->beforeDateLen = (int)(cert->srcIdx - startIdx);
    else
        cert->afterDateLen  = (int)(cert->srcIdx - startIdx);

#ifndef NO_ASN_TIME_CHECK
    if (verify != NO_VERIFY && verify != VERIFY_SKIP_DATE &&
            (! AsnSkipDateCheck) &&
            !XVALIDATE_DATE(date, format, dateType, length)) {
        if (dateType == ASN_BEFORE) {
            WOLFSSL_ERROR_VERBOSE(ASN_BEFORE_DATE_E);
            return ASN_BEFORE_DATE_E;
        }
        else {
            WOLFSSL_ERROR_VERBOSE(ASN_AFTER_DATE_E);
            return ASN_AFTER_DATE_E;
        }
    }
#else
    (void)verify;
#endif

    return 0;
}

static int GetValidity(DecodedCert* cert, int verify, int maxIdx)
{
    int length;
    int badDate = 0;

    if (GetSequence(cert->source, &cert->srcIdx, &length, (word32)maxIdx) < 0)
        return ASN_PARSE_E;

    maxIdx = (int)cert->srcIdx + length;

    if (GetDate(cert, ASN_BEFORE, verify, maxIdx) < 0)
        badDate = ASN_BEFORE_DATE_E; /* continue parsing */

    if (GetDate(cert, ASN_AFTER, verify, maxIdx) < 0)
        return ASN_AFTER_DATE_E;

    if (badDate != 0)
        return badDate;

    return 0;
}
#endif

#ifndef NO_CERTS
static int GetSigAlg(DecodedCert* cert, word32* sigOid, word32 maxIdx)
{
    int length;
    word32 endSeqIdx;

    if (GetSequence(cert->source, &cert->srcIdx, &length, maxIdx) < 0)
        return ASN_PARSE_E;
    endSeqIdx = cert->srcIdx + (word32)length;

    if (GetObjectId(cert->source, &cert->srcIdx, sigOid, oidSigType,
                    maxIdx) < 0) {
        return ASN_OBJECT_ID_E;
    }

    if (cert->srcIdx != endSeqIdx) {
#ifdef WC_RSA_PSS
        if (*sigOid == CTC_RSASSAPSS) {
            /* cert->srcIdx is at start of parameters TLV (NULL or SEQUENCE) */
            word32 tmpIdx = cert->srcIdx;
            byte tag;
            int len;

            WOLFSSL_MSG("Cert sigAlg is RSASSA-PSS; decoding params");
            if (GetHeader(cert->source, &tag, &tmpIdx, &len, endSeqIdx, 0) < 0) {
                return ASN_PARSE_E;
            }
            cert->sigParamsIndex  = cert->srcIdx;
            cert->sigParamsLength = (word32)((tmpIdx - cert->srcIdx) + len);
        }
        else
#endif
        /* Only allowed a ASN NULL header with zero length. */
        if  (endSeqIdx - cert->srcIdx != 2)
            return ASN_PARSE_E;
        else {
            byte tag;
            if (GetASNTag(cert->source, &cert->srcIdx, &tag, endSeqIdx) != 0)
                return ASN_PARSE_E;
            if (tag != ASN_TAG_NULL)
                return ASN_PARSE_E;
        }
    }

    cert->srcIdx = endSeqIdx;

    return 0;
}
#endif

#ifndef NO_CERTS
int wc_GetPubX509(DecodedCert* cert, int verify, int* badDate)
{
    int ret;

    if (cert == NULL || badDate == NULL)
        return BAD_FUNC_ARG;

    *badDate = 0;
    if ( (ret = GetCertHeader(cert)) < 0)
        return ret;

    WOLFSSL_MSG("Got Cert Header");

#ifdef WOLFSSL_CERT_REQ
    if (!cert->isCSR) {
#endif
        /* Using the sigIndex as the upper bound because that's where the
         * actual certificate data ends. */
        if ((ret = GetSigAlg(cert, &cert->signatureOID, cert->sigIndex)) < 0)
            return ret;

        WOLFSSL_MSG("Got Algo ID");

        if ( (ret = GetName(cert, ASN_ISSUER, (int)cert->sigIndex)) < 0)
            return ret;

        if ( (ret = GetValidity(cert, verify, (int)cert->sigIndex)) < 0)
            *badDate = ret;
#ifdef WOLFSSL_CERT_REQ
    }
#endif

    if ( (ret = GetName(cert, ASN_SUBJECT, (int)cert->sigIndex)) < 0)
        return ret;

    WOLFSSL_MSG("Got Subject Name");
    return ret;
}

int DecodeToKey(DecodedCert* cert, int verify)
{
    int badDate = 0;
    int ret;

#if defined(HAVE_RPK)

    /* Raw Public Key certificate has only a SubjectPublicKeyInfo structure
     * as its contents. So try to call GetCertKey to get public key from it.
     * If it fails, the cert should be a X509 cert and proceed to process as
     * x509 cert. */
    ret = GetCertKey(cert, cert->source, &cert->srcIdx, cert->maxIdx);
    if (ret == 0) {
        WOLFSSL_MSG("Raw Public Key certificate found and parsed");
        cert->isRPK = 1;
        return ret;
    }
#endif /* HAVE_RPK */

    if ( (ret = wc_GetPubX509(cert, verify, &badDate)) < 0)
        return ret;

    /* Determine if self signed */
#ifdef WOLFSSL_CERT_REQ
    if (cert->isCSR)
        cert->selfSigned = 1;
    else
#endif
    {
        cert->selfSigned = XMEMCMP(cert->issuerHash, cert->subjectHash,
            KEYID_SIZE) == 0 ? 1 : 0;
    }

    ret = GetCertKey(cert, cert->source, &cert->srcIdx, cert->maxIdx);
    if (ret != 0)
        return ret;

    WOLFSSL_MSG("Got Key");

    if (badDate != 0)
        return badDate;

    return ret;
}

static int GetSignature(DecodedCert* cert)
{
    int length;
    int ret;

    ret = CheckBitString(cert->source, &cert->srcIdx, &length, cert->maxIdx, 1,
                         NULL);
    if (ret != 0)
        return ret;

    cert->sigLength = (word32)length;
    cert->signature = &cert->source[cert->srcIdx];
    cert->srcIdx += cert->sigLength;

    if (cert->srcIdx != cert->maxIdx)
        return ASN_PARSE_E;

    return 0;
}

#endif
/* Set an octet header when length is only 7-bit.
 *
 * @param [in] len     Length of data in OCTET_STRING. Value must be <= 127.
 * @param [in] output  Buffer to encode ASN.1 header.
 * @return  Length of ASN.1 header.
 */
static word32 SetOctetString8Bit(word32 len, byte* output)
{
    output[0] = ASN_OCTET_STRING;
    output[1] = (byte)len;
    return 2;
}
static word32 SetDigest(const byte* digest, word32 digSz, byte* output)
{
    word32 idx = SetOctetString8Bit(digSz, output);
    XMEMCPY(&output[idx], digest, digSz);

    return idx + digSz;
}

static word32 SetAlgoIDImpl(int algoOID, byte* output, int type, int curveSz,
                            byte absentParams)
{
    word32 tagSz, idSz, seqSz, algoSz = 0;
    const  byte* algoName = 0;
    byte   ID_Length[1 + MAX_LENGTH_SZ];
    byte   seqArray[MAX_SEQ_SZ + 1];  /* add object_id to end */
    word32    length = 0;

    tagSz = ((type == oidHashType ||
             (type == oidSigType && !IsSigAlgoECC((word32)algoOID)) ||
             (type == oidKeyType && algoOID == RSAk)) &&
                (absentParams == FALSE)) ? 2U : 0U;
    algoName = OidFromId((word32)algoOID, (word32)type, &algoSz);
    if (algoName == NULL) {
        WOLFSSL_MSG("Unknown Algorithm");
        return 0;
    }

    idSz  = (word32)SetObjectId((int)algoSz, ID_Length);
    seqSz = SetSequence(idSz + algoSz + tagSz + (word32)curveSz, seqArray);

    /* Copy only algo to output for DSA keys */
    if (algoOID == DSAk && output) {
        XMEMCPY(output, ID_Length, idSz);
        XMEMCPY(output + idSz, algoName, algoSz);
        if (tagSz == 2)
            SetASNNull(&output[seqSz + idSz + algoSz]);
    }
    else if (output) {
        XMEMCPY(output, seqArray, seqSz);
        XMEMCPY(output + seqSz, ID_Length, idSz);
        XMEMCPY(output + seqSz + idSz, algoName, algoSz);
        if (tagSz == 2)
            SetASNNull(&output[seqSz + idSz + algoSz]);
    }

    if (algoOID == DSAk)
        length = idSz + algoSz + tagSz;
    else
        length = seqSz + idSz + algoSz + tagSz;

    return length;
}

word32 wc_EncodeSignature(byte* out, const byte* digest, word32 digSz,
                          int hashOID)
{
    byte digArray[MAX_ENCODED_DIG_SZ];
    byte algoArray[MAX_ALGO_SZ];
    byte seqArray[MAX_SEQ_SZ];
    word32 encDigSz, algoSz, seqSz;

    encDigSz = SetDigest(digest, digSz, digArray);
    algoSz   = SetAlgoID(hashOID, algoArray, oidHashType, 0);
    seqSz    = SetSequence(encDigSz + algoSz, seqArray);

    XMEMCPY(out, seqArray, seqSz);
    XMEMCPY(out + seqSz, algoArray, algoSz);
    XMEMCPY(out + seqSz + algoSz, digArray, encDigSz);

    return encDigSz + algoSz + seqSz;
}

#ifndef NO_CERTS
static void AddAltName(DecodedCert* cert, DNS_entry* dnsEntry)
{
#if (defined(WOLFSSL_ASN_ALL) || defined(OPENSSL_EXTRA)) && \
    !defined(WOLFSSL_ALT_NAMES_NO_REV)
    /* logic to add alt name to end of list */
    dnsEntry->next = NULL;
    if (cert->altNames == NULL) {
        /* First on list */
        cert->altNames = dnsEntry;
    }
    else {
        DNS_entry* temp = cert->altNames;

        /* Find end */
        for (; (temp->next != NULL); temp = temp->next);

        /* Add to end */
        temp->next = dnsEntry;
    }
#else
    dnsEntry->next = cert->altNames;
    cert->altNames = dnsEntry;
#endif
}

#if defined(WOLFSSL_SEP)
/* return 0 on success */
static int DecodeSepHwAltName(DecodedCert* cert, const byte* input,
    word32* idxIn, word32 sz)
{
    word32 idx = *idxIn;
    int  strLen;
    int  ret;
    byte tag;

    /* Certificates issued with this OID in the subject alt name are for
     * verifying signatures created on a module.
     * RFC 4108 Section 5. */
    if (cert->hwType != NULL) {
        WOLFSSL_MSG("\tAlready seen Hardware Module Name");
        return ASN_PARSE_E;
    }

    if (GetASNTag(input, &idx, &tag, sz) < 0) {
        return ASN_PARSE_E;
    }

    if (tag != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
        WOLFSSL_MSG("\twrong type");
        return ASN_PARSE_E;
    }

    if (GetLength(input, &idx, &strLen, sz) < 0) {
        WOLFSSL_MSG("\tfail: str len");
        return ASN_PARSE_E;
    }

    if (GetSequence(input, &idx, &strLen, sz) < 0) {
        WOLFSSL_MSG("\tBad Sequence");
        return ASN_PARSE_E;
    }

    ret = GetASNObjectId(input, &idx, &strLen, sz);
    if (ret != 0) {
        WOLFSSL_MSG("\tbad OID");
        return ret;
    }

    cert->hwType = (byte*)XMALLOC((size_t)strLen, cert->heap,
                                  DYNAMIC_TYPE_X509_EXT);
    if (cert->hwType == NULL) {
        WOLFSSL_MSG("\tOut of Memory");
        return MEMORY_E;
    }

    XMEMCPY(cert->hwType, &input[idx], (size_t)strLen);
    cert->hwTypeSz = strLen;
    idx += (word32)strLen;

    ret = GetOctetString(input, &idx, &strLen, sz);
    if (ret < 0) {
        XFREE(cert->hwType, cert->heap, DYNAMIC_TYPE_X509_EXT);
        cert->hwType = NULL;
        return ret;
    }

    cert->hwSerialNum = (byte*)XMALLOC((size_t)strLen + 1, cert->heap,
                                       DYNAMIC_TYPE_X509_EXT);
    if (cert->hwSerialNum == NULL) {
        WOLFSSL_MSG("\tOut of Memory");
        XFREE(cert->hwType, cert->heap, DYNAMIC_TYPE_X509_EXT);
        cert->hwType = NULL;
        return MEMORY_E;
    }

    XMEMCPY(cert->hwSerialNum, &input[idx], (size_t)strLen);
    cert->hwSerialNum[strLen] = '\0';
    cert->hwSerialNumSz = strLen;
    idx += (word32)strLen;

    *idxIn = idx;
    return 0;
}
#endif

/* return 0 on success */
static int DecodeConstructedOtherName(DecodedCert* cert, const byte* input,
        word32* idx, word32 sz, int oid)
{
    int ret    = 0;
    int strLen = 0;
    byte tag;
    DNS_entry* dnsEntry = NULL;

    if (GetASNTag(input, idx, &tag, sz) < 0) {
        ret = ASN_PARSE_E;
    }

    if (ret == 0 && (tag != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))) {
        ret = ASN_PARSE_E;
    }

    if (ret == 0 && (GetLength(input, idx, &strLen, sz) < 0)) {
        ret = ASN_PARSE_E;
    }

    if (ret == 0) {
        dnsEntry = AltNameNew(cert->heap);
        if (dnsEntry == NULL) {
            WOLFSSL_MSG("\tOut of Memory");
            return MEMORY_E;
        }

        switch (oid) {
        #ifdef WOLFSSL_FPKI
            case FASCN_OID:
                ret = GetOctetString(input, idx, &strLen, sz);
                if (ret > 0) {
                    ret = 0;
                }
                break;
        #endif /* WOLFSSL_FPKI */
            case UPN_OID:
                if (GetASNTag(input, idx, &tag, sz) < 0) {
                    ret = ASN_PARSE_E;
                }

                if (ret == 0 &&
                        tag != ASN_PRINTABLE_STRING && tag != ASN_UTF8STRING &&
                                    tag != ASN_IA5_STRING) {
                    WOLFSSL_MSG("Was expecting a string for UPN");
                    ret = ASN_PARSE_E;
                }

                if (ret == 0 && (GetLength(input, idx, &strLen, sz) < 0)) {
                    WOLFSSL_MSG("Was expecting a string for UPN");
                    ret = ASN_PARSE_E;
                }
                break;

            default:
                WOLFSSL_MSG("Unknown constructed other name, skipping");
                XFREE(dnsEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                dnsEntry = NULL;
        }
    }

    if (ret == 0 && dnsEntry != NULL) {
        dnsEntry->type = ASN_OTHER_TYPE;
        dnsEntry->len = strLen;
        dnsEntry->name = (char*)XMALLOC((size_t)strLen + 1, cert->heap,
            DYNAMIC_TYPE_ALTNAME);
    #ifdef WOLFSSL_FPKI
        dnsEntry->oidSum = oid;
    #endif /* WOLFSSL_FPKI */
        if (dnsEntry->name == NULL) {
            WOLFSSL_MSG("\tOut of Memory");
            ret = MEMORY_E;
        }
        else {
            dnsEntry->nameStored = 1;
            XMEMCPY((void *)(wc_ptr_t)dnsEntry->name, &input[*idx],
                    (size_t)strLen);
            ((char *)(wc_ptr_t)dnsEntry->name)[strLen] = '\0';
            AddAltName(cert, dnsEntry);
        }
    }

    if (ret == 0) {
        *idx += (word32)strLen;
    }
    else {
        XFREE(dnsEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
    }

    return ret;
}

static int DecodeAltNames(const byte* input, word32 sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;
    word32 numNames = 0;

    WOLFSSL_ENTER("DecodeAltNames");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tBad Sequence");
        return ASN_PARSE_E;
    }

    if (length == 0) {
        /* RFC 5280 4.2.1.6.  Subject Alternative Name
           If the subjectAltName extension is present, the sequence MUST
           contain at least one entry. */
        WOLFSSL_ERROR_VERBOSE(ASN_PARSE_E);
        return ASN_PARSE_E;
    }

#ifdef OPENSSL_ALL
    cert->extSubjAltNameSrc = input;
    cert->extSubjAltNameSz = sz;
#endif

    cert->weOwnAltNames = 1;

    while (length > 0) {
        byte current_byte;

        /* Verify idx can't overflow input buffer */
        if (idx >= (word32)sz) {
            WOLFSSL_MSG("\tBad Index");
            return BUFFER_E;
        }

        numNames++;
        if (numNames > WOLFSSL_MAX_ALT_NAMES) {
            WOLFSSL_MSG("\tToo many subject alternative names");
            return ASN_ALT_NAME_E;
        }

        current_byte = input[idx++];
        length--;

        /* Save DNS Type names in the altNames list. */
        /* Save Other Type names in the cert's OidMap */
        if (current_byte == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE)) {
            DNS_entry* dnsEntry;
            int strLen;
            word32 lenStartIdx = idx;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (int)(idx - lenStartIdx);

            dnsEntry = AltNameNew(cert->heap);
            if (dnsEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            dnsEntry->type = ASN_DNS_TYPE;
            dnsEntry->name = (char*)XMALLOC((size_t)strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (dnsEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(dnsEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            dnsEntry->nameStored = 1;
            dnsEntry->len = strLen;
            XMEMCPY((void *)(wc_ptr_t)dnsEntry->name, &input[idx],
                    (size_t)strLen);
            ((char *)(wc_ptr_t)dnsEntry->name)[strLen] = '\0';

            AddAltName(cert, dnsEntry);

            if (strLen > length) {
                return ASN_PARSE_E;
            }
            length -= strLen;
            idx    += (word32)strLen;
        }
    #ifndef IGNORE_NAME_CONSTRAINTS
        else if (current_byte ==
                (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_DIR_TYPE)) {
            DNS_entry* dirEntry;
            int strLen;
            word32 lenStartIdx = idx;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }

            if (GetSequence(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: seq length");
                return ASN_PARSE_E;
            }
            length -= (int)(idx - lenStartIdx);

            dirEntry = AltNameNew(cert->heap);
            if (dirEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            dirEntry->type = ASN_DIR_TYPE;
            dirEntry->name = (char*)XMALLOC((size_t)strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (dirEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(dirEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            dirEntry->nameStored = 1;
            dirEntry->len = strLen;
            XMEMCPY((void *)(wc_ptr_t)dirEntry->name, &input[idx],
                    (size_t)strLen);
            ((char *)(wc_ptr_t)dirEntry->name)[strLen] = '\0';
            dirEntry->next = cert->altDirNames;
            cert->altDirNames = dirEntry;

            if (strLen > length) {
                return ASN_PARSE_E;
            }
            length -= strLen;
            idx    += (word32)strLen;
        }
        else if (current_byte == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE)) {
            DNS_entry* emailEntry;
            int strLen;
            word32 lenStartIdx = idx;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (int)(idx - lenStartIdx);

            emailEntry = AltNameNew(cert->heap);
            if (emailEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }
            emailEntry->nameStored = 1;
            emailEntry->type = ASN_RFC822_TYPE;
            emailEntry->name = (char*)XMALLOC((size_t)strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (emailEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(emailEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            emailEntry->len = strLen;
            XMEMCPY((void *)(wc_ptr_t)emailEntry->name, &input[idx],
                    (size_t)strLen);
            ((char *)(wc_ptr_t)emailEntry->name)[strLen] = '\0';

            emailEntry->next = cert->altEmailNames;
            cert->altEmailNames = emailEntry;

            if (strLen > length) {
                return ASN_PARSE_E;
            }
            length -= strLen;
            idx    += (word32)strLen;
        }
        else if (current_byte == (ASN_CONTEXT_SPECIFIC | ASN_URI_TYPE)) {
            DNS_entry* uriEntry;
            int strLen;
            word32 lenStartIdx = idx;

            WOLFSSL_MSG("\tPutting URI into list but not using");
            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (int)(idx - lenStartIdx);

            /* check that strLen at index is not past input buffer */
            if ((word32)strLen + idx > sz) {
                return BUFFER_E;
            }

        #if !defined(WOLFSSL_NO_ASN_STRICT) && !defined(WOLFSSL_FPKI)
            /* Verify RFC 5280 Sec 4.2.1.6 rule:
                "The name MUST NOT be a relative URI"
                As per RFC 3986 Sec 4.3, an absolute URI is only required to contain
                a scheme and hier-part.  So the only strict requirement is a ':'
                being present after the scheme.  If a '/' is present as part of the
                hier-part, it must come after the ':' (see RFC 3986 Sec 3). */

            {
                word32 i;

                /* skip past scheme (i.e http,ftp,...) finding first ':' char */
                for (i = 0; i < (word32)strLen; i++) {
                    if (input[idx + i] == ':') {
                        break;
                    }
                    if (input[idx + i] == '/') {
                        WOLFSSL_MSG("\tAlt Name must be absolute URI");
                        WOLFSSL_ERROR_VERBOSE(ASN_ALT_NAME_E);
                        return ASN_ALT_NAME_E;
                    }
                }

                /* test hier-part is empty */
                if (i == 0 || i == (word32)strLen) {
                    WOLFSSL_MSG("\tEmpty or malformed URI");
                    WOLFSSL_ERROR_VERBOSE(ASN_ALT_NAME_E);
                    return ASN_ALT_NAME_E;
                }

                /* test if scheme is missing */
                if (input[idx + i] != ':') {
                    WOLFSSL_MSG("\tAlt Name must be absolute URI");
                    WOLFSSL_ERROR_VERBOSE(ASN_ALT_NAME_E);
                    return ASN_ALT_NAME_E;
                }
            }
        #endif

            uriEntry = AltNameNew(cert->heap);
            if (uriEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }
            uriEntry->nameStored = 1;
            uriEntry->type = ASN_URI_TYPE;
            uriEntry->name = (char*)XMALLOC((size_t)strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (uriEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(uriEntry, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            uriEntry->len = strLen;
            XMEMCPY((void *)(wc_ptr_t)uriEntry->name, &input[idx],
                    (size_t)strLen);
            ((char *)(wc_ptr_t)uriEntry->name)[strLen] = '\0';

            AddAltName(cert, uriEntry);

            if (strLen > length) {
                return ASN_PARSE_E;
            }
            length -= strLen;
            idx    += (word32)strLen;
        }
#ifdef WOLFSSL_IP_ALT_NAME
        else if (current_byte == (ASN_CONTEXT_SPECIFIC | ASN_IP_TYPE)) {
            DNS_entry* ipAddr;
            int strLen;
            word32 lenStartIdx = idx;
            WOLFSSL_MSG("Decoding Subject Alt. Name: IP Address");

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);
            /* check that strLen at index is not past input buffer */
            if (strLen + idx > sz) {
                return BUFFER_E;
            }

            ipAddr = AltNameNew(cert->heap);
            if (ipAddr == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }
            ipAddr->nameStored = 1;
            ipAddr->type = ASN_IP_TYPE;
            ipAddr->name = (char*)XMALLOC((size_t)strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (ipAddr->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(ipAddr, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            ipAddr->len = strLen;
            XMEMCPY((void *)(wc_ptr_t)ipAddr->name, &input[idx], strLen);
            ((char *)(wc_ptr_t)ipAddr->name)[strLen] = '\0';

            if (GenerateDNSEntryIPString(ipAddr, cert->heap) != 0) {
                WOLFSSL_MSG("\tOut of Memory for IP string");
                XFREE((void *)(wc_ptr_t)ipAddr->name, cert->heap,
                      DYNAMIC_TYPE_ALTNAME);
                XFREE(ipAddr, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            AddAltName(cert, ipAddr);

            if (strLen > length) {
                return ASN_PARSE_E;
            }
            length -= strLen;
            idx    += (word32)strLen;
        }
#endif /* WOLFSSL_IP_ALT_NAME */
#ifdef WOLFSSL_RID_ALT_NAME
        else if (current_byte == (ASN_CONTEXT_SPECIFIC | ASN_RID_TYPE)) {
            DNS_entry* rid;
            int strLen;
            word32 lenStartIdx = idx;
            WOLFSSL_MSG("Decoding Subject Alt. Name: Registered Id");

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: str length");
                return ASN_PARSE_E;
            }
            length -= (idx - lenStartIdx);
            /* check that strLen at index is not past input buffer */
            if (strLen + idx > sz) {
                return BUFFER_E;
            }

            rid = AltNameNew(cert->heap);
            if (rid == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            rid->type = ASN_RID_TYPE;
            rid->name = (char*)XMALLOC((size_t)strLen + 1, cert->heap,
                                         DYNAMIC_TYPE_ALTNAME);
            if (rid->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(rid, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            rid->nameStored = 1;
            rid->len = strLen;
            XMEMCPY((void *)(wc_ptr_t)rid->name, &input[idx], strLen);
            ((char *)(wc_ptr_t)rid->name)[strLen] = '\0';

            if (GenerateDNSEntryRIDString(rid, cert->heap) != 0) {
                WOLFSSL_MSG("\tOut of Memory for registered Id string");
                XFREE((void *)(wc_ptr_t)rid->name, cert->heap,
                      DYNAMIC_TYPE_ALTNAME);
                XFREE(rid, cert->heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }

            AddAltName(cert, rid);

            if (strLen > length) {
                return ASN_PARSE_E;
            }
            length -= strLen;
            idx    += (word32)strLen;
        }
#endif /* WOLFSSL_RID_ALT_NAME */
#endif /* IGNORE_NAME_CONSTRAINTS */
        else if (current_byte ==
                (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_OTHER_TYPE)) {
            int strLen;
            word32 lenStartIdx = idx;
            word32 oid = 0;
            int    ret = 0;

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: other name length");
                return ASN_PARSE_E;
            }
            /* Consume the rest of this sequence. */
            if ((int)((word32)strLen + idx - lenStartIdx) > length) {
                return ASN_PARSE_E;
            }
            length -= (int)(((word32)strLen + idx - lenStartIdx));

            if (GetObjectId(input, &idx, &oid, oidCertAltNameType, sz) < 0) {
                WOLFSSL_MSG("\tbad OID");
                return ASN_PARSE_E;
            }

            /* handle parsing other type alt names */
            switch (oid) {
            #ifdef WOLFSSL_SEP
                case HW_NAME_OID:
                    ret = DecodeSepHwAltName(cert, input, &idx, sz);
                    if (ret != 0)
                        return ret;
                    break;
            #endif /* WOLFSSL_SEP */
            #ifdef WOLFSSL_FPKI
                case FASCN_OID:
                case UPN_OID:
                    ret = DecodeConstructedOtherName(cert, input, &idx, sz,
                            oid);
                    if (ret != 0)
                        return ret;
                    break;
            #endif /* WOLFSSL_FPKI */

                default:
                    WOLFSSL_MSG("\tUnsupported other name type, skipping");
                    if (GetLength(input, &idx, &strLen, sz) < 0) {
                        /* check to skip constructed other names too */
                        if (DecodeConstructedOtherName(cert, input, &idx, sz,
                                    (int)oid) != 0) {
                            WOLFSSL_MSG("\tfail: unsupported other name length");
                            return ASN_PARSE_E;
                        }
                    }
                    else {
                        idx += (word32)strLen;
                    }
            }
            (void)ret;
        }
        else {
            int strLen;
            word32 lenStartIdx = idx;

            WOLFSSL_MSG("\tUnsupported name type, skipping");

            if (GetLength(input, &idx, &strLen, sz) < 0) {
                WOLFSSL_MSG("\tfail: unsupported name length");
                return ASN_PARSE_E;
            }
            if ((int)((word32)strLen + idx - lenStartIdx) > length) {
                return ASN_PARSE_E;
            }
            length -= (int)((word32)strLen + idx - lenStartIdx);
            idx += (word32)strLen;
        }
    }

    return 0;
}

int DecodeBasicCaConstraint(const byte* input, int sz, byte *isCa,
                            word16 *pathLength, byte *pathLengthSet)
{
    word32 idx = 0;
    int length = 0;
    int ret;

    WOLFSSL_ENTER("DecodeBasicCaConstraint");

    if (GetSequence(input, &idx, &length, (word32)sz) < 0) {
        WOLFSSL_MSG("\tfail: bad SEQUENCE");
        return ASN_PARSE_E;
    }

    if (length == 0)
        return 0;

    /* If the basic ca constraint is false, this extension may be named, but
     * left empty. So, if the length is 0, just return. */

    ret = GetBoolean(input, &idx, (word32)sz);

    /* Removed logic for WOLFSSL_X509_BASICCONS_INT which was mistreating the
     * pathlen value as if it were the CA Boolean value 7/2/2021 - KH.
     * When CA Boolean not asserted use the default value "False" */
    if (ret < 0) {
        WOLFSSL_MSG("\tfail: constraint not valid BOOLEAN, set default FALSE");
        ret = 0;
    }

    *isCa = ret ? 1 : 0;

    /* If there isn't any more data, return. */
    if (idx >= (word32)sz) {
        return 0;
    }

    ret = GetInteger16Bit(input, &idx, (word32)sz);
    if (ret < 0)
        return ret;
    else if (ret > WOLFSSL_MAX_PATH_LEN) {
        WOLFSSL_ERROR_VERBOSE(ASN_PATHLEN_SIZE_E);
        return ASN_PATHLEN_SIZE_E;
    }

    *pathLength = (word16)ret;
    *pathLengthSet = 1;

    return 0;
}

static int DecodeCrlDist(const byte* input, word32 sz, DecodedCert* cert)
{
    word32 idx = 0, localIdx;
    int length = 0;
    byte tag   = 0;

    WOLFSSL_ENTER("DecodeCrlDist");

    cert->extCrlInfoRaw = input;
    cert->extCrlInfoRawSz = (int)sz;

    /* Unwrap the list of Distribution Points*/
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    /* Unwrap a single Distribution Point */
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    /* The Distribution Point has three explicit optional members
     *  First check for a DistributionPointName
     */
    localIdx = idx;
    if (GetASNTag(input, &localIdx, &tag, sz) == 0 &&
            tag == (ASN_CONSTRUCTED | DISTRIBUTION_POINT))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        localIdx = idx;
        if (GetASNTag(input, &localIdx, &tag, sz) == 0 &&
                tag == (ASN_CONSTRUCTED | CRLDP_FULL_NAME))
        {
            idx++;
            if (GetLength(input, &idx, &length, sz) < 0)
                return ASN_PARSE_E;

            localIdx = idx;
            if (GetASNTag(input, &localIdx, &tag, sz) == 0 &&
                    tag == GENERALNAME_URI)
            {
                idx++;
                if (GetLength(input, &idx, &length, sz) < 0)
                    return ASN_PARSE_E;

                cert->extCrlInfoSz = length;
                cert->extCrlInfo = input + idx;
                idx += (word32)length;
            }
            else
                /* This isn't a URI, skip it. */
                idx += (word32)length;
        }
        else {
            /* This isn't a FULLNAME, skip it. */
            idx += (word32)length;
        }
    }

    /* Check for reasonFlags */
    localIdx = idx;
    if (idx < (word32)sz &&
        GetASNTag(input, &localIdx, &tag, sz) == 0 &&
        tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;
        idx += (word32)length;
    }

    /* Check for cRLIssuer */
    localIdx = idx;
    if (idx < (word32)sz &&
        GetASNTag(input, &localIdx, &tag, sz) == 0 &&
        tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 2))
    {
        idx++;
        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;
        idx += (word32)length;
    }

    if (idx < (word32)sz)
    {
        WOLFSSL_MSG("\tThere are more CRL Distribution Point records, "
                   "but we only use the first one.");
    }

    return 0;
}

static int DecodeAuthInfo(const byte* input, word32 sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;
    byte b = 0;
    word32 oid;
    int aiaIdx;

    WOLFSSL_ENTER("DecodeAuthInfo");

    /* Unwrap the list of AIAs */
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    while ((idx < (word32)sz)) {
        /* Unwrap a single AIA */
        if (GetSequence(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        oid = 0;
        if (GetObjectId(input, &idx, &oid, oidCertAuthInfoType, sz) < 0) {
            return ASN_PARSE_E;
        }

        /* Only supporting URIs right now. */
        if (GetASNTag(input, &idx, &b, sz) < 0)
            return ASN_PARSE_E;

        if (GetLength(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        if (b == GENERALNAME_URI) {
            /* Add to AIA list if space. */
            aiaIdx = cert->extAuthInfoListSz;
            if (aiaIdx < WOLFSSL_MAX_AIA_ENTRIES) {
                cert->extAuthInfoList[aiaIdx].method = oid;
                cert->extAuthInfoList[aiaIdx].uri = input + idx;
                cert->extAuthInfoList[aiaIdx].uriSz = (word32)length;
                cert->extAuthInfoListSz++;
            }
            else {
                cert->extAuthInfoListOverflow = 1;
                WOLFSSL_MSG("AIA list overflow");
            }
        }

        /* Set first ocsp entry */
        if (b == GENERALNAME_URI && oid == AIA_OCSP_OID &&
                cert->extAuthInfo == NULL) {
            cert->extAuthInfoSz = length;
            cert->extAuthInfo = input + idx;
        }
    #ifdef WOLFSSL_ASN_CA_ISSUER
        /* Set first CaIssuers entry */
        else if ((b == GENERALNAME_URI) && oid == AIA_CA_ISSUER_OID &&
                cert->extAuthInfoCaIssuer == NULL)
        {
            cert->extAuthInfoCaIssuerSz = length;
            cert->extAuthInfoCaIssuer = input + idx;
        }
    #endif
        idx += (word32)length;
    }

    return 0;
}

int DecodeAuthKeyId(const byte* input, word32 sz, const byte **extAuthKeyId,
        word32 *extAuthKeyIdSz, const byte **extAuthKeyIdIssuer,
        word32 *extAuthKeyIdIssuerSz, const byte **extAuthKeyIdIssuerSN,
        word32 *extAuthKeyIdIssuerSNSz)
{
    word32 idx = 0;
    int length = 0;
    byte tag;

    WOLFSSL_ENTER("DecodeAuthKeyId");

    if (extAuthKeyId)
        *extAuthKeyId = NULL;
    if (extAuthKeyIdSz)
        *extAuthKeyIdSz = 0;

    if (extAuthKeyIdIssuer)
        *extAuthKeyIdIssuer = NULL;
    if (extAuthKeyIdIssuerSz)
        *extAuthKeyIdIssuerSz = 0;

    if (extAuthKeyIdIssuerSN)
        *extAuthKeyIdIssuerSN = NULL;
    if (extAuthKeyIdIssuerSNSz)
        *extAuthKeyIdIssuerSNSz = 0;

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }

    if (GetASNTag(input, &idx, &tag, sz) < 0) {
        return ASN_PARSE_E;
    }

    if (tag != (ASN_CONTEXT_SPECIFIC | 0)) {
        WOLFSSL_MSG("\tinfo: OPTIONAL item 0, not available");
        return 0;
    }

    if (GetLength(input, &idx, &length, sz) <= 0) {
        WOLFSSL_MSG("\tfail: extension data length");
        return ASN_PARSE_E;
    }

    if (extAuthKeyIdSz)
        *extAuthKeyIdSz = length;
    if (extAuthKeyId)
        *extAuthKeyId = &input[idx];
    return 0;

}

int DecodeKeyUsage(const byte* input, word32 sz, word16 *extKeyUsage)
{
    word32 idx = 0;
    int length;
    int ret;
    WOLFSSL_ENTER("DecodeKeyUsage");

    ret = CheckBitString(input, &idx, &length, sz, 0, NULL);
    if (ret != 0)
        return ret;

    if (length == 0 || length > 2)
        return ASN_PARSE_E;

    *extKeyUsage = (word16)(input[idx]);
    if (length == 2)
        *extKeyUsage |= (word16)(input[idx+1] << 8);

    return 0;
}

int DecodeExtKeyUsage(const byte* input, word32 sz,
        const byte **extExtKeyUsageSrc, word32 *extExtKeyUsageSz,
        word32 *extExtKeyUsageCount, byte *extExtKeyUsage,
        byte *extExtKeyUsageSsh)
{
    word32 idx = 0, oid;
    int length, ret;

    WOLFSSL_ENTER("DecodeExtKeyUsage");

    (void) extExtKeyUsageSrc;
    (void) extExtKeyUsageSz;
    (void) extExtKeyUsageCount;
    (void) extExtKeyUsageSsh;

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    *extExtKeyUsageSrc = NULL;
    *extExtKeyUsageSz = 0;
    *extExtKeyUsageCount = 0;
#endif
    *extExtKeyUsage = 0;
#ifdef WOLFSSL_WOLFSSH
    *extExtKeyUsageSsh = 0;
#endif

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    *extExtKeyUsageSrc = input + idx;
    *extExtKeyUsageSz = length;
#endif

    while (idx < (word32)sz) {
        ret = GetObjectId(input, &idx, &oid, oidCertKeyUseType, sz);
        if (ret == WC_NO_ERR_TRACE(ASN_UNKNOWN_OID_E))
            continue;
        else if (ret < 0)
            return ret;

        switch (oid) {
            case EKU_ANY_OID:
                *extExtKeyUsage |= EXTKEYUSE_ANY;
                break;
            case EKU_SERVER_AUTH_OID:
                *extExtKeyUsage |= EXTKEYUSE_SERVER_AUTH;
                break;
            case EKU_CLIENT_AUTH_OID:
                *extExtKeyUsage |= EXTKEYUSE_CLIENT_AUTH;
                break;
            case EKU_CODESIGNING_OID:
                *extExtKeyUsage |= EXTKEYUSE_CODESIGN;
                break;
            case EKU_EMAILPROTECT_OID:
                *extExtKeyUsage |= EXTKEYUSE_EMAILPROT;
                break;
            case EKU_TIMESTAMP_OID:
                *extExtKeyUsage |= EXTKEYUSE_TIMESTAMP;
                break;
            case EKU_OCSP_SIGN_OID:
                *extExtKeyUsage |= EXTKEYUSE_OCSP_SIGN;
                break;
            #ifdef WOLFSSL_WOLFSSH
            case EKU_SSH_CLIENT_AUTH_OID:
                *extExtKeyUsageSsh |= EXTKEYUSE_SSH_CLIENT_AUTH;
                break;
            case EKU_SSH_MSCL_OID:
                *extExtKeyUsageSsh |= EXTKEYUSE_SSH_MSCL;
                break;
            case EKU_SSH_KP_CLIENT_AUTH_OID:
                *extExtKeyUsageSsh |= EXTKEYUSE_SSH_KP_CLIENT_AUTH;
                break;
            #endif /* WOLFSSL_WOLFSSH */
            default:
                break;
        }

    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        (*extExtKeyUsageCount)++;
    #endif
    }

    return 0;
}

#ifndef IGNORE_NAME_CONSTRAINTS
static int DecodeSubtree(const byte* input, word32 sz, Base_entry** head,
                         word32 limit, void* heap)
{
    word32 idx = 0;
    int ret = 0;
    word32 cnt = 0;

    (void)heap;

    while (idx < (word32)sz) {
        int seqLength, strLength;
        word32 nameIdx;
        byte b, bType;

        if (limit > 0) {
            cnt++;
            if (cnt > limit) {
                WOLFSSL_MSG("too many name constraints");
                return ASN_NAME_INVALID_E;
            }
        }

        if (GetSequence(input, &idx, &seqLength, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        if (idx >= (word32)sz) {
            WOLFSSL_MSG("\tfail: expecting tag");
            return ASN_PARSE_E;
        }

        nameIdx = idx;
        b = input[nameIdx++];

        if (GetLength(input, &nameIdx, &strLength, sz) <= 0) {
            WOLFSSL_MSG("\tinvalid length");
            return ASN_PARSE_E;
        }

        /* Get type, LSB 4-bits */
        bType = (byte)(b & ASN_TYPE_MASK);

        if (bType == ASN_DNS_TYPE || bType == ASN_RFC822_TYPE ||
            bType == ASN_DIR_TYPE || bType == ASN_IP_TYPE ||
            bType == ASN_URI_TYPE) {
            Base_entry* entry;

            /* if constructed has leading sequence */
            if (b & ASN_CONSTRUCTED) {
                if (GetSequence(input, &nameIdx, &strLength, sz) < 0) {
                    WOLFSSL_MSG("\tfail: constructed be a SEQUENCE");
                    return ASN_PARSE_E;
                }
            }

            entry = (Base_entry*)XMALLOC(sizeof(Base_entry), heap,
                                                          DYNAMIC_TYPE_ALTNAME);
            if (entry == NULL) {
                WOLFSSL_MSG("allocate error");
                return MEMORY_E;
            }

            entry->name = (char*)XMALLOC((size_t)strLength+1, heap,
                DYNAMIC_TYPE_ALTNAME);
            if (entry->name == NULL) {
                WOLFSSL_MSG("allocate error");
                XFREE(entry, heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }

            XMEMCPY(entry->name, &input[nameIdx], (size_t)strLength);
            entry->name[strLength] = '\0';
            entry->nameSz = strLength;
            entry->type = bType;

            entry->next = *head;
            *head = entry;
        }

        idx += (word32)seqLength;
    }

    return ret;
}

static int DecodeNameConstraints(const byte* input, word32 sz,
    DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;

    WOLFSSL_ENTER("DecodeNameConstraints");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }

    while (idx < (word32)sz) {
        byte b = input[idx++];
        Base_entry** subtree = NULL;

        if (GetLength(input, &idx, &length, sz) <= 0) {
            WOLFSSL_MSG("\tinvalid length");
            return ASN_PARSE_E;
        }

        if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
            subtree = &cert->permittedNames;
        else if (b == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
            subtree = &cert->excludedNames;
        else {
            WOLFSSL_MSG("\tinvalid subtree");
            return ASN_PARSE_E;
        }

        if (DecodeSubtree(input + idx, (word32)length, subtree,
                WOLFSSL_MAX_NAME_CONSTRAINTS, cert->heap) < 0) {
            WOLFSSL_MSG("\terror parsing subtree");
            return ASN_PARSE_E;
        }

        idx += (word32)length;
    }

    return 0;
}

#endif
#if defined(WOLFSSL_SEP) || defined(WOLFSSL_CERT_EXT)
static int DecodeCertPolicy(const byte* input, word32 sz, DecodedCert* cert)
{
    word32 idx = 0;
    word32 oldIdx;
    int policy_length = 0;
    int ret;
    int total_length = 0;
#if defined(WOLFSSL_CERT_EXT) && !defined(WOLFSSL_DUP_CERTPOL)
    int i;
#endif

    WOLFSSL_ENTER("DecodeCertPolicy");

    /* Check if cert is null before dereferencing below */
    if (cert == NULL)
        return BAD_FUNC_ARG;

#if defined(WOLFSSL_CERT_EXT)
        cert->extCertPoliciesNb = 0;
#endif

    if (GetSequence(input, &idx, &total_length, sz) < 0) {
        WOLFSSL_MSG("\tGet CertPolicy total seq failed");
        return ASN_PARSE_E;
    }

    /* Validate total length */
    if (total_length > (int)(sz - idx)) {
        WOLFSSL_MSG("\tCertPolicy length mismatch");
        return ASN_PARSE_E;
    }

    /* Unwrap certificatePolicies */
    do {
        int length = 0;

        if (GetSequence(input, &idx, &policy_length, sz) < 0) {
            WOLFSSL_MSG("\tGet CertPolicy seq failed");
            return ASN_PARSE_E;
        }

        oldIdx = idx;
        ret = GetASNObjectId(input, &idx, &length, sz);
        if (ret != 0)
            return ret;
        policy_length -= (int)(idx - oldIdx);

        if (length > 0) {
            /* Verify length won't overrun buffer */
            if (length > (int)(sz - idx)) {
                WOLFSSL_MSG("\tCertPolicy length exceeds input buffer");
                return ASN_PARSE_E;
            }

    #ifdef WOLFSSL_SEP
            if (cert->deviceType == NULL) {
                cert->deviceType = (byte*)XMALLOC((size_t)length, cert->heap,
                                                        DYNAMIC_TYPE_X509_EXT);
                if (cert->deviceType == NULL) {
                    WOLFSSL_MSG("\tCouldn't alloc memory for deviceType");
                    return MEMORY_E;
                }
                cert->deviceTypeSz = length;
                XMEMCPY(cert->deviceType, input + idx, (size_t)length);
            }
    #endif

    #ifdef WOLFSSL_CERT_EXT
            /* decode cert policy */
            if (DecodePolicyOID(cert->extCertPolicies[
                                cert->extCertPoliciesNb], MAX_CERTPOL_SZ,
                                input + idx, length) <= 0) {
                WOLFSSL_MSG("\tCouldn't decode CertPolicy");
                WOLFSSL_ERROR_VERBOSE(ASN_PARSE_E);
                return ASN_PARSE_E;
            }
        #ifndef WOLFSSL_DUP_CERTPOL
            /* From RFC 5280 section 4.2.1.4 "A certificate policy OID MUST
             * NOT appear more than once in a certificate policies
             * extension". This is a sanity check for duplicates.
             * extCertPolicies should only have OID values, additional
             * qualifiers need to be stored in a separate array. */
            for (i = 0; i < cert->extCertPoliciesNb; i++) {
                if (XMEMCMP(cert->extCertPolicies[i],
                            cert->extCertPolicies[cert->extCertPoliciesNb],
                            MAX_CERTPOL_SZ) == 0) {
                    WOLFSSL_MSG("Duplicate policy OIDs not allowed");
                    WOLFSSL_MSG("Use WOLFSSL_DUP_CERTPOL if wanted");
                    WOLFSSL_ERROR_VERBOSE(CERTPOLICIES_E);
                    return CERTPOLICIES_E;
                }
            }
        #endif /* !WOLFSSL_DUP_CERTPOL */
            cert->extCertPoliciesNb++;
    #endif
        }
        idx += (word32)policy_length;
    } while((int)idx < total_length
    #ifdef WOLFSSL_CERT_EXT
        && cert->extCertPoliciesNb < MAX_CERTPOL_NB
    #endif
    );

    WOLFSSL_LEAVE("DecodeCertPolicy", 0);
    return 0;
}

#endif
#ifdef WOLFSSL_SUBJ_DIR_ATTR
static int DecodeSubjDirAttr(const byte* input, word32 sz, DecodedCert* cert)
{
    word32 idx = 0;
    int length = 0;
    int ret = 0;

    WOLFSSL_ENTER("DecodeSubjDirAttr");

#ifdef OPENSSL_ALL
    cert->extSubjDirAttrSrc = input;
    cert->extSubjDirAttrSz = sz;
#endif /* OPENSSL_ALL */

    /* Unwrap the list of Attributes */
    if (GetSequence(input, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (length == 0) {
        /* RFC 5280 4.2.1.8.  Subject Directory Attributes
           If the subjectDirectoryAttributes extension is present, the
           sequence MUST contain at least one entry. */
        WOLFSSL_ERROR_VERBOSE(ASN_PARSE_E);
        return ASN_PARSE_E;
    }

    /* length is the length of the list contents */
    while (idx < (word32)sz) {
        word32 oid;

        if (GetSequence(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        if (GetObjectId(input, &idx, &oid, oidSubjDirAttrType, sz) < 0)
            return ASN_PARSE_E;

        if (GetSet(input, &idx, &length, sz) < 0)
            return ASN_PARSE_E;

        /* There may be more than one countryOfCitizenship, but save the
         * first one for now. */
        if (oid == SDA_COC_OID) {
            byte tag;

            if (GetHeader(input, &tag, &idx, &length, sz, 1) < 0)
                return ASN_PARSE_E;

            if (length != COUNTRY_CODE_LEN)
                return ASN_PARSE_E;

            if (tag == ASN_PRINTABLE_STRING) {
                XMEMCPY(cert->countryOfCitizenship,
                        input + idx, COUNTRY_CODE_LEN);
                cert->countryOfCitizenship[COUNTRY_CODE_LEN] = 0;
            }
        }
        idx += length;
    }

    return ret;
}

#endif
static int DecodeCertExtensions(DecodedCert* cert)
{
    int ret = 0;
    word32 idx = 0;
    word32 sz = (word32)cert->extensionsSz;
    const byte* input = cert->extensions;
    int length;
    word32 oid;
    byte critical = 0;
    byte criticalFail = 0;
    byte tag = 0;

    WOLFSSL_ENTER("DecodeCertExtensions");

    if (input == NULL || sz == 0)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_CERT_REQ
    if (!cert->isCSR)
#endif
    { /* Not included in CSR */
        if (GetASNTag(input, &idx, &tag, sz) < 0) {
            return ASN_PARSE_E;
        }

        if (tag != ASN_EXTENSIONS) {
            WOLFSSL_MSG("\tfail: should be an EXTENSIONS");
            return ASN_PARSE_E;
        }

        if (GetLength(input, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: invalid length");
            return ASN_PARSE_E;
        }
    }

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE (1)");
        return ASN_PARSE_E;
    }

    while (idx < (word32)sz) {
        word32 localIdx;

        if (GetSequence(input, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        oid = 0;
        if ((ret = GetObjectId(input, &idx, &oid, oidCertExtType, sz)) < 0) {
            WOLFSSL_MSG("\tfail: OBJECT ID");
            return ret;
        }

        /* check for critical flag */
        critical = 0;
        if ((idx + 1) > (word32)sz) {
            WOLFSSL_MSG("\tfail: malformed buffer");
            return BUFFER_E;
        }

        localIdx = idx;
        if (GetASNTag(input, &localIdx, &tag, sz) == 0) {
            if (tag == ASN_BOOLEAN) {
                ret = GetBoolean(input, &idx, sz);
                if (ret < 0) {
                    WOLFSSL_MSG("\tfail: critical boolean");
                    return ret;
                }

                critical = (byte)ret;
            }
        }

        /* process the extension based on the OID */
        ret = GetOctetString(input, &idx, &length, sz);
        if (ret < 0) {
            WOLFSSL_MSG("\tfail: bad OCTET STRING");
            return ret;
        }

        ret = DecodeExtensionType(input + idx, (word32)length, oid, critical,
            cert, NULL);
        if (ret == WC_NO_ERR_TRACE(ASN_CRIT_EXT_E)) {
            ret = 0;
            criticalFail = 1;
        }
        if (ret < 0)
            goto end;
        idx += (word32)length;
    }

    ret = criticalFail ? ASN_CRIT_EXT_E : 0;
end:
    return ret;
}

#if defined(WOLFSSL_SMALL_CERT_VERIFY) || defined(OPENSSL_EXTRA)
static int CheckCertSignature_ex(const byte* cert, word32 certSz, void* heap,
        void* cm, const byte* pubKey, word32 pubKeySz, int pubKeyOID, int req)
{
#if !defined(WOLFSSL_SMALL_STACK) || defined(WOLFSSL_NO_MALLOC)
    SignatureCtx  sigCtx[1];
#else
    SignatureCtx* sigCtx;
#endif
    byte          hash[KEYID_SIZE];
    Signer*       ca = NULL;
    word32        idx = 0;
    int           len;
    word32        tbsCertIdx = 0;
    word32        sigIndex   = 0;
    word32        signatureOID = 0;
    word32        oid = 0;
    word32        issuerIdx = 0;
    word32        issuerSz  = 0;
#ifndef NO_SKID
    int           extLen = 0;
    word32        extIdx = 0;
    word32        extEndIdx = 0;
    int           extAuthKeyIdSet = 0;
#endif
    int           ret = 0;
    word32        localIdx;
    byte          tag;
    const byte*   sigParams = NULL;
    word32        sigParamsSz = 0;


    if (cert == NULL) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    sigCtx = (SignatureCtx*)XMALLOC(sizeof(*sigCtx), heap, DYNAMIC_TYPE_SIGNATURE);
    if (sigCtx == NULL)
        return MEMORY_E;
#endif

    InitSignatureCtx(sigCtx, heap, INVALID_DEVID);

    /* Certificate SEQUENCE */
    if (GetSequence(cert, &idx, &len, certSz) < 0)
        ret = ASN_PARSE_E;
    if (ret == 0) {
        tbsCertIdx = idx;

        /* TBSCertificate SEQUENCE */
        if (GetSequence(cert, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        sigIndex = len + idx;

        if ((idx + 1) > certSz)
            ret = BUFFER_E;
    }
    if (ret == 0) {
        /* version - optional */
        localIdx = idx;
        if (GetASNTag(cert, &localIdx, &tag, certSz) == 0) {
            if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED)) {
                idx++;
                if (GetLength(cert, &idx, &len, certSz) < 0)
                    ret = ASN_PARSE_E;
                idx += len;
            }
        }
    }

    if (ret == 0) {
        /* serialNumber */
        if (GetASNHeader(cert, ASN_INTEGER, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        idx += len;

        /* signature */
        if (!req) {
            if (GetAlgoId(cert, &idx, &signatureOID, oidSigType, certSz) < 0)
                ret = ASN_PARSE_E;
        #ifdef WC_RSA_PSS
            else if (signatureOID == CTC_RSASSAPSS) {
                int start = idx;
                sigParams = cert + idx;
                if (GetSequence(cert, &idx, &len, certSz) < 0)
                    ret = ASN_PARSE_E;
                if (ret == 0) {
                    idx += len;
                    sigParamsSz = idx - start;
                }
            }
        #endif
        }
    }

    if (ret == 0) {
        issuerIdx = idx;
        /* issuer for cert or subject for csr */
        if (GetSequence(cert, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        issuerSz = len + idx - issuerIdx;
    }
#ifndef NO_SKID
    if (!req && ret == 0) {
        idx += len;

        /* validity */
        if (GetSequence(cert, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (!req && ret == 0) {
        idx += len;

        /* subject */
        if (GetSequence(cert, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        idx += len;

        /* subjectPublicKeyInfo */
        if (GetSequence(cert, &idx, &len, certSz) < 0)
            ret = ASN_PARSE_E;
    }
    if (req && ret == 0) {
        idx += len;

        /* attributes */
        if (GetASNHeader_ex(cert,
                ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED, &idx,
                &len, certSz, 1) < 0)
            ret = ASN_PARSE_E;
    }
    if (!req) {
        if (ret == 0) {
            idx += len;

            if ((idx + 1) > certSz)
                ret = BUFFER_E;
        }
        if (ret == 0) {
            /* issuerUniqueID - optional */
            localIdx = idx;
            if (GetASNTag(cert, &localIdx, &tag, certSz) == 0) {
                if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1)) {
                    idx++;
                    if (GetLength(cert, &idx, &len, certSz) < 0)
                        ret = ASN_PARSE_E;
                    idx += len;
                }
            }
        }
        if (ret == 0) {
            if ((idx + 1) > certSz)
                ret = BUFFER_E;
        }
        if (ret == 0) {
            /* subjectUniqueID - optional */
            localIdx = idx;
            if (GetASNTag(cert, &localIdx, &tag, certSz) == 0) {
                if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2)) {
                    idx++;
                    if (GetLength(cert, &idx, &len, certSz) < 0)
                        ret = ASN_PARSE_E;
                    idx += len;
                }
            }
        }

        if (ret == 0) {
            if ((idx + 1) > certSz)
                ret = BUFFER_E;
        }
        /* extensions - optional */
        localIdx = idx;
        if (ret == 0 && GetASNTag(cert, &localIdx, &tag, certSz) == 0 &&
                tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 3)) {
            idx++;
            if (GetLength(cert, &idx, &extLen, certSz) < 0)
                ret = ASN_PARSE_E;
            if (ret == 0) {
                if (GetSequence(cert, &idx, &extLen, certSz) < 0)
                    ret = ASN_PARSE_E;
            }
            if (ret == 0) {
                extEndIdx = idx + extLen;

                /* Check each extension for the ones we want. */
                while (ret == 0 && idx < extEndIdx) {
                    if (GetSequence(cert, &idx, &len, certSz) < 0)
                        ret = ASN_PARSE_E;
                    if (ret == 0) {
                        extIdx = idx;
                        if (GetObjectId(cert, &extIdx, &oid, oidCertExtType,
                                                                  certSz) < 0) {
                            ret = ASN_PARSE_E;
                        }

                        if (ret == 0) {
                            if ((extIdx + 1) > certSz)
                                ret = BUFFER_E;
                        }
                    }

                    if (ret == 0) {
                        localIdx = extIdx;
                        if (GetASNTag(cert, &localIdx, &tag, certSz) == 0 &&
                                tag == ASN_BOOLEAN) {
                            if (GetBoolean(cert, &extIdx, certSz) < 0)
                                ret = ASN_PARSE_E;
                        }
                    }
                    if (ret == 0) {
                        if (GetOctetString(cert, &extIdx, &extLen, certSz) < 0)
                            ret = ASN_PARSE_E;
                    }

                    if (ret == 0) {
                        switch (oid) {
                        case AUTH_KEY_OID:
                            if (GetSequence(cert, &extIdx, &extLen, certSz) < 0)
                                ret = ASN_PARSE_E;

                            if (ret == 0 && (extIdx + 1) >= certSz)
                                ret = BUFFER_E;

                            if (ret == 0 &&
                                    GetASNTag(cert, &extIdx, &tag, certSz) == 0 &&
                                    tag == (ASN_CONTEXT_SPECIFIC | 0)) {
                                if (GetLength(cert, &extIdx, &extLen, certSz) <= 0)
                                    ret = ASN_PARSE_E;
                                if (ret == 0) {
                                    extAuthKeyIdSet = 1;
                                    /* Get the hash or hash of the hash if wrong
                                     * size. */
                                    ret = GetHashId(cert + extIdx, extLen,
                                        hash, HashIdAlg(signatureOID));
                                }
                            }
                            break;

                        default:
                            break;
                        }
                    }
                    idx += len;
                }
            }
        }
    }
    else if (ret == 0) {
        idx += len;
    }

    if (ret == 0 && pubKey == NULL) {
        if (extAuthKeyIdSet)
            ca = GetCA(cm, hash);
        if (ca == NULL) {
            ret = CalcHashId_ex(cert + issuerIdx, issuerSz, hash,
                HashIdAlg(signatureOID));
            if (ret == 0)
                ca = GetCAByName(cm, hash);
        }
    }
#else
    if (ret == 0 && pubKey == NULL) {
        ret = CalcHashId_ex(cert + issuerIdx, issuerSz, hash,
            HashIdAlg(signatureOID));
        if (ret == 0)
            ca = GetCA(cm, hash);
    }
#endif /* !NO_SKID */
    if (ca == NULL && pubKey == NULL)
        ret = ASN_NO_SIGNER_E;

    if (ret == 0) {
        idx = sigIndex;
        /* signatureAlgorithm */
        if (GetAlgoId(cert, &idx, &oid, oidSigType, certSz) < 0)
            ret = ASN_PARSE_E;
    #ifdef WC_RSA_PSS
        else if (signatureOID == CTC_RSASSAPSS) {
            word32 sz = idx;
            const byte* params = cert + idx;
            if (GetSequence(cert, &idx, &len, certSz) < 0)
                ret = ASN_PARSE_E;
            if (ret == 0) {
                idx += len;
                sz = idx - sz;

                if (req) {
                    if ((sz != sigParamsSz) ||
                                        (XMEMCMP(sigParams, params, sz) != 0)) {
                        ret = ASN_PARSE_E;
                    }
                }
                else {
                    sigParams = params;
                    sigParamsSz = sz;
                }
            }
        }
    #endif
        /* In CSR signature data is not present in body */
        if (req)
            signatureOID = oid;
    }
    if (ret == 0) {
        if (oid != signatureOID)
            ret = ASN_SIG_OID_E;
    }
    if (ret == 0) {
        /* signatureValue */
        if (CheckBitString(cert, &idx, &len, certSz, 1, NULL) < 0)
            ret = ASN_PARSE_E;
    }

    if (ret == 0) {
        if (pubKey != NULL) {
            ret = ConfirmSignature(sigCtx, cert + tbsCertIdx,
                sigIndex - tbsCertIdx, pubKey, pubKeySz, pubKeyOID,
                cert + idx, len, signatureOID, sigParams, sigParamsSz, NULL);
        }
        else {
            ret = ConfirmSignature(sigCtx, cert + tbsCertIdx,
                sigIndex - tbsCertIdx, ca->publicKey, ca->pubKeySize,
                ca->keyOID, cert + idx, len, signatureOID, sigParams,
                sigParamsSz, NULL);
        }
        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(ret);
            WOLFSSL_MSG("Confirm signature failed");
        }
    }

    FreeSignatureCtx(sigCtx);
    WC_FREE_VAR_EX(sigCtx, heap, DYNAMIC_TYPE_SIGNATURE);
    return ret;
}

#endif
#endif
int wc_GetSerialNumber(const byte* input, word32* inOutIdx,
    byte* serial, int* serialSz, word32 maxIdx)
{
    int result = 0;
    int ret;

    WOLFSSL_ENTER("wc_GetSerialNumber");

    if (serial == NULL || input == NULL || serialSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* First byte is ASN type */
    if ((*inOutIdx+1) > maxIdx) {
        WOLFSSL_MSG("Bad idx first");
        return BUFFER_E;
    }

    ret = GetASNInt(input, inOutIdx, serialSz, maxIdx);
    if (ret != 0)
        return ret;

    if (*serialSz > EXTERNAL_SERIAL_SIZE || *serialSz <= 0) {
        WOLFSSL_MSG("Serial size bad");
        WOLFSSL_ERROR_VERBOSE(ASN_PARSE_E);
        return ASN_PARSE_E;
    }

    /* return serial */
    XMEMCPY(serial, &input[*inOutIdx], (size_t)*serialSz);
    *inOutIdx += (word32)*serialSz;

    return result;
}

#ifndef NO_CERTS
#if !defined(NO_RSA) && \
(defined(WOLFSSL_KEY_TO_DER) || defined(WOLFSSL_CERT_GEN))
static int SetRsaPublicKey(byte* output, RsaKey* key, int outLen,
                           int with_header)
{
    int  nSz, eSz;
    word32 seqSz, algoSz = 0, headSz = 0, bitStringSz = 0, idx;
    byte seq[MAX_SEQ_SZ];
    byte headSeq[MAX_SEQ_SZ];
    byte bitString[1 + MAX_LENGTH_SZ + 1];
    byte algo[MAX_ALGO_SZ]; /* 20 bytes */

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    nSz = SetASNIntMP(&key->n, MAX_RSA_INT_SZ, NULL);

    if (nSz < 0)
        return nSz;

    eSz = SetASNIntMP(&key->e, MAX_RSA_INT_SZ, NULL);

    if (eSz < 0)
        return eSz;
    seqSz = SetSequence((word32)(nSz + eSz), seq);

    /* headers */
    if (with_header) {
        algoSz = SetAlgoID(RSAk, algo, oidKeyType, 0);
        bitStringSz = SetBitString(seqSz + (word32)(nSz + eSz), 0, bitString);
        headSz = SetSequence((word32)(nSz + eSz) + seqSz + bitStringSz + algoSz,
                             headSeq);
    }

    /* if getting length only */
    if (output == NULL) {
        return (int)(headSz + algoSz + bitStringSz + seqSz) + nSz + eSz;
    }

    /* check output size */
    if (((int)(headSz + algoSz + bitStringSz + seqSz) + nSz + eSz) > outLen) {
        return BUFFER_E;
    }

    /* write output */
    idx = 0;
    if (with_header) {
        /* header size */
        XMEMCPY(output + idx, headSeq, headSz);
        idx += headSz;
        /* algo */
        XMEMCPY(output + idx, algo, algoSz);
        idx += algoSz;
        /* bit string */
        XMEMCPY(output + idx, bitString, bitStringSz);
        idx += bitStringSz;
    }

    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx += seqSz;
    /* n */
    nSz = SetASNIntMP(&key->n, nSz, output + idx);
    idx += (word32)nSz;
    /* e */
    eSz = SetASNIntMP(&key->e, eSz, output + idx);
    idx += (word32)eSz;

    return (int)idx;
}

#endif
#endif
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_TO_DER)
int wc_RsaKeyToDer(RsaKey* key, byte* output, word32 inLen)
{
    int ret = 0, i;
    int mpSz;
    word32 seqSz = 0, verSz = 0, intTotalLen = 0, outLen = 0;
    byte  seq[MAX_SEQ_SZ];
    byte  ver[MAX_VERSION_SZ];
    mp_int* keyInt;
#ifndef WOLFSSL_NO_MALLOC
    word32 rawLen;
    byte* tmps[RSA_INTS];
    word32 sizes[RSA_INTS];
#endif

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (key->type != RSA_PRIVATE)
        return BAD_FUNC_ARG;

#ifndef WOLFSSL_NO_MALLOC
    for (i = 0; i < RSA_INTS; i++)
        tmps[i] = NULL;
#endif

    /* write all big ints from key to DER tmps */
    for (i = 0; i < RSA_INTS; i++) {
        keyInt = GetRsaInt(key, i);
        ret = mp_unsigned_bin_size(keyInt);
        if (ret < 0)
            break;
#ifndef WOLFSSL_NO_MALLOC
        rawLen = (word32)ret + 1;
        ret = 0;
        if (output != NULL) {
            tmps[i] = (byte*)XMALLOC(rawLen + MAX_SEQ_SZ, key->heap,
                                 DYNAMIC_TYPE_RSA);
            if (tmps[i] == NULL) {
                ret = MEMORY_E;
                break;
            }
        }
        mpSz = SetASNIntMP(keyInt, MAX_RSA_INT_SZ, tmps[i]);
#else
        ret = 0;
        mpSz = SetASNIntMP(keyInt, MAX_RSA_INT_SZ, NULL);
#endif
        if (mpSz < 0) {
            ret = mpSz;
            break;
        }
    #ifndef WOLFSSL_NO_MALLOC
        sizes[i] = (word32)mpSz;
    #endif
        intTotalLen += (word32)mpSz;
    }

    if (ret == 0) {
        /* make headers */
        ret = SetMyVersion(0, ver, FALSE);
    }

    if (ret >= 0) {
        verSz = (word32)ret;
        ret = 0;
        seqSz = SetSequence(verSz + intTotalLen, seq);
        outLen = seqSz + verSz + intTotalLen;
        if (output != NULL && outLen > inLen)
            ret = BUFFER_E;
    }
    if (ret == 0 && output != NULL) {
        word32 j;

        /* write to output */
        XMEMCPY(output, seq, seqSz);
        j = seqSz;
        XMEMCPY(output + j, ver, verSz);
        j += verSz;

        for (i = 0; i < RSA_INTS; i++) {
/* copy from tmps if we have malloc, otherwise re-export with buffer */
#ifndef WOLFSSL_NO_MALLOC
            XMEMCPY(output + j, tmps[i], sizes[i]);
            j += sizes[i];
#else
            keyInt = GetRsaInt(key, i);
            ret = mp_unsigned_bin_size(keyInt);
            if (ret < 0)
                break;
            ret = 0;
            /* This won't overrun output due to the outLen check above */
            mpSz = SetASNIntMP(keyInt, MAX_RSA_INT_SZ, output + j);
            if (mpSz < 0) {
                ret = mpSz;
                break;
            }
            j += mpSz;
#endif
        }
    }

#ifndef WOLFSSL_NO_MALLOC
    for (i = 0; i < RSA_INTS; i++) {
        if (tmps[i])
            XFREE(tmps[i], key->heap, DYNAMIC_TYPE_RSA);
    }
#endif

    if (ret == 0)
        ret = (int)outLen;
    return ret;
}

#endif
#ifndef NO_CERTS
#ifdef WOLFSSL_CERT_GEN
#ifdef WOLFSSL_CERT_REQ

/* Write a set header to output */
static word32 SetPrintableString(word32 len, byte* output)
{
    output[0] = ASN_PRINTABLE_STRING;
    return SetLength(len, output + 1) + 1;
}

static word32 SetUTF8String(word32 len, byte* output)
{
    output[0] = ASN_UTF8STRING;
    return SetLength(len, output + 1) + 1;
}


#endif

/* Copy Dates from cert, return bytes written */
static int CopyValidity(byte* output, Cert* cert)
{
    word32 seqSz;

    WOLFSSL_ENTER("CopyValidity");

    /* headers and output */
    seqSz = SetSequence((word32)(cert->beforeDateSz + cert->afterDateSz),
                        output);
    if (output) {
        XMEMCPY(output + seqSz, cert->beforeDate, (size_t)cert->beforeDateSz);
        XMEMCPY(output + seqSz + cert->beforeDateSz, cert->afterDate,
                (size_t)cert->afterDateSz);
    }
    return (int)seqSz + cert->beforeDateSz + cert->afterDateSz;
}


/*
 Extensions ::= SEQUENCE OF Extension

 Extension ::= SEQUENCE {
 extnId     OBJECT IDENTIFIER,
 critical   BOOLEAN DEFAULT FALSE,
 extnValue  OCTET STRING }
 */

/* encode all extensions, return total bytes written */
static int SetExtensions(byte* out, word32 outSz, int *IdxInOut,
                         const byte* ext, int extSz)
{
    if (out == NULL || IdxInOut == NULL || ext == NULL)
        return BAD_FUNC_ARG;

    if (outSz < (word32)(*IdxInOut+extSz))
        return BUFFER_E;

    XMEMCPY(&out[*IdxInOut], ext, (size_t)extSz);  /* extensions */
    *IdxInOut += extSz;

    return *IdxInOut;
}

/* encode extensions header, return total bytes written */
static int SetExtensionsHeader(byte* out, word32 outSz, word32 extSz)
{
    byte sequence[MAX_SEQ_SZ];
    byte len[MAX_LENGTH_SZ];
    word32 seqSz, lenSz, idx = 0;

    if (out == NULL)
        return BAD_FUNC_ARG;

    if (outSz < 3)
        return BUFFER_E;

    seqSz = SetSequence(extSz, sequence);

    /* encode extensions length provided */
    lenSz = SetLength(extSz+seqSz, len);

    if (outSz < (word32)(lenSz+seqSz+1))
        return BUFFER_E;

    out[idx++] = ASN_EXTENSIONS; /* extensions id */
    XMEMCPY(&out[idx], len, lenSz);  /* length */
    idx += lenSz;

    XMEMCPY(&out[idx], sequence, seqSz);  /* sequence */
    idx += seqSz;

    return (int)idx;
}


/* encode CA basic constraints true with path length
 * return total bytes written */
static int SetCaWithPathLen(byte* out, word32 outSz, byte pathLen)
{
    /* ASN1->DER sequence for Basic Constraints True and path length */
    const byte caPathLenBasicConstASN1[] = {
        0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04,
        0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01,
        0x00
    };

    if (out == NULL)
        return BAD_FUNC_ARG;

    if (outSz < sizeof(caPathLenBasicConstASN1))
        return BUFFER_E;

    XMEMCPY(out, caPathLenBasicConstASN1, sizeof(caPathLenBasicConstASN1));

    out[sizeof(caPathLenBasicConstASN1)-1] = pathLen;

    return (int)sizeof(caPathLenBasicConstASN1);
}

/* encode CA basic constraints
 * return total bytes written */
static int SetCaEx(byte* out, word32 outSz, byte isCa)
{
    /* ASN1->DER sequence for Basic Constraints True */
    const byte caBasicConstASN1[] = {
        0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04,
        0x05, 0x30, 0x03, 0x01, 0x01, 0xff
    };

    if (out == NULL)
        return BAD_FUNC_ARG;

    if (outSz < sizeof(caBasicConstASN1))
        return BUFFER_E;

    XMEMCPY(out, caBasicConstASN1, sizeof(caBasicConstASN1));

    if (!isCa) {
        out[sizeof(caBasicConstASN1)-1] = isCa;
    }

    return (int)sizeof(caBasicConstASN1);
}

/* encode CA basic constraints true
 * return total bytes written */
static int SetCa(byte* out, word32 outSz)
{
    return SetCaEx(out, outSz, 1);
}

/* encode basic constraints without CA Boolean
 * return total bytes written */
static int SetBC(byte* out, word32 outSz)
{
    /* ASN1->DER sequence for Basic Constraint without CA Boolean */
 const byte BasicConstASN1[] = {
        0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04,
        0x02, 0x30, 0x00
    };

    if (out == NULL)
        return BAD_FUNC_ARG;

    if (outSz < sizeof(BasicConstASN1))
        return BUFFER_E;

    XMEMCPY(out, BasicConstASN1, sizeof(BasicConstASN1));

    return (int)sizeof(BasicConstASN1);
}

#ifdef WOLFSSL_CERT_EXT
/* encode OID and associated value, return total bytes written */
static int SetOidValue(byte* out, word32 outSz, const byte *oid, word32 oidSz,
                       byte *in, word32 inSz)
{
    word32 idx = 0;

    if (out == NULL || oid == NULL || in == NULL)
        return BAD_FUNC_ARG;
    if (inSz >= ASN_LONG_LENGTH)
        return BAD_FUNC_ARG;
    if (oidSz >= ASN_LONG_LENGTH)
        return BAD_FUNC_ARG;
    if (inSz + oidSz + 1 >= ASN_LONG_LENGTH)
        return BAD_FUNC_ARG;

    if (outSz < 3)
        return BUFFER_E;

    /* sequence,  + 1 => byte to put value size */
    idx = SetSequence(inSz + oidSz + 1, out);

    if ((idx + inSz + oidSz + 1) > outSz)
        return BUFFER_E;

    XMEMCPY(out+idx, oid, oidSz);
    idx += oidSz;
    out[idx++] = (byte)inSz;
    XMEMCPY(out+idx, in, inSz);

    return (int)(idx+inSz);
}

/* encode Subject Key Identifier, return total bytes written
 * RFC5280 : non-critical */
static int SetSKID(byte* output, word32 outSz, const byte *input, word32 length)
{
    byte skid_len[1 + MAX_LENGTH_SZ];
    byte skid_enc_len[MAX_LENGTH_SZ];
    word32 idx = 0, skid_lenSz, skid_enc_lenSz;
    const byte skid_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04 };

    if (output == NULL || input == NULL)
        return BAD_FUNC_ARG;

    /* Octet String header */
    skid_lenSz = SetOctetString(length, skid_len);

    /* length of encoded value */
    skid_enc_lenSz = SetLength(length + skid_lenSz, skid_enc_len);

    if (outSz < 3)
        return BUFFER_E;

    idx = SetSequence(length + (word32)sizeof(skid_oid) + skid_lenSz +
                      skid_enc_lenSz, output);

    if ((length + sizeof(skid_oid) + skid_lenSz + skid_enc_lenSz) > outSz)
        return BUFFER_E;

    /* put oid */
    XMEMCPY(output+idx, skid_oid, sizeof(skid_oid));
    idx += sizeof(skid_oid);

    /* put encoded len */
    XMEMCPY(output+idx, skid_enc_len, skid_enc_lenSz);
    idx += skid_enc_lenSz;

    /* put octet header */
    XMEMCPY(output+idx, skid_len, skid_lenSz);
    idx += skid_lenSz;

    /* put value */
    XMEMCPY(output+idx, input, length);
    idx += length;

    return (int)idx;
}

/* encode Authority Key Identifier, return total bytes written
 * RFC5280 : non-critical */
static int SetAKID(byte* output, word32 outSz, byte *input, word32 length,
                   byte rawAkid)
{
    int     enc_valSz;
    byte enc_val_buf[MAX_KID_SZ];
    byte* enc_val;
    const byte akid_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x23 };
    const byte akid_cs[] = { 0x80 };
    word32 inSeqSz, idx;

    (void)rawAkid;

    if (output == NULL || input == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_AKID_NAME
    if (rawAkid) {
        enc_val = input;
        enc_valSz = length;
    }
    else
#endif
    {
        enc_val = enc_val_buf;
        enc_valSz = (int)length + 3 + (int)sizeof(akid_cs);
        if (enc_valSz > (int)sizeof(enc_val_buf))
            return BAD_FUNC_ARG;

        /* sequence for ContentSpec & value */
        enc_valSz = SetOidValue(enc_val, (word32)enc_valSz, akid_cs,
                                sizeof(akid_cs), input, length);
        if (enc_valSz <= 0)
            return enc_valSz;
    }

    /* The size of the extension sequence contents */
    inSeqSz = (word32)sizeof(akid_oid) +
        SetOctetString((word32)enc_valSz, NULL) + (word32)enc_valSz;

    if (SetSequence(inSeqSz, NULL) + inSeqSz > outSz)
        return BAD_FUNC_ARG;

    /* Write out the sequence header */
    idx = SetSequence(inSeqSz, output);

    /* Write out OID */
    XMEMCPY(output + idx, akid_oid, sizeof(akid_oid));
    idx += sizeof(akid_oid);

    /* Write out AKID */
    idx += SetOctetString((word32)enc_valSz, output + idx);
    XMEMCPY(output + idx, enc_val, (size_t)enc_valSz);

    return (int)idx + enc_valSz;
}

#ifdef WOLFSSL_ACME_OID
/* encode RFC 8737 id-pe-acmeIdentifier extension, return total bytes written
 * RFC8737 : critical */
static int SetAcmeIdentifier(byte* output, word32 outSz, const byte* digest,
                             word32 digestSz)
{
    byte inner[1 + MAX_LENGTH_SZ + WC_SHA256_DIGEST_SIZE];
    word32 innerSz;
    const byte acmeId_oid[] = { 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07,
                                0x01, 0x1F, 0x01, 0x01, 0xFF, 0x04 };

    if (output == NULL || digest == NULL)
        return BAD_FUNC_ARG;
    if (digestSz != WC_SHA256_DIGEST_SIZE)
        return BAD_FUNC_ARG;

    innerSz = SetOctetString(digestSz, inner);
    XMEMCPY(inner + innerSz, digest, digestSz);
    innerSz += digestSz;

    return SetOidValue(output, outSz, acmeId_oid, sizeof(acmeId_oid),
                       inner, innerSz);
}
#endif /* WOLFSSL_ACME_OID */

/* encode Key Usage, return total bytes written
 * RFC5280 : critical */
static int SetKeyUsage(byte* output, word32 outSz, word16 input)
{
    byte ku[5];
    word32 idx;
    const byte keyusage_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x0f,
                                         0x01, 0x01, 0xff, 0x04};
    if (output == NULL)
        return BAD_FUNC_ARG;

    idx = SetBitString16Bit(input, ku);
    return SetOidValue(output, outSz, keyusage_oid, sizeof(keyusage_oid),
                       ku, idx);
}

static int SetOjectIdValue(byte* output, word32 outSz, word32* idx,
    const byte* oid, word32 oidSz)
{
    /* verify room */
    if (*idx + 2 + oidSz >= outSz)
        return ASN_PARSE_E;

    *idx += (word32)SetObjectId((int)oidSz, &output[*idx]);
    XMEMCPY(&output[*idx], oid, oidSz);
    *idx += oidSz;

    return 0;
}

static int SetExtKeyUsage(Cert* cert, byte* output, word32 outSz, byte input)
{
    word32 idx = 0, oidListSz = 0, totalSz;
    int ret = 0;
    const byte extkeyusage_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x25 };

    if (output == NULL)
        return BAD_FUNC_ARG;

    /* Skip to OID List */
    totalSz = 2 + sizeof(extkeyusage_oid) + 4;
    idx = totalSz;

    /* Build OID List */
    /* If any set, then just use it */
    if (input & EXTKEYUSE_ANY) {
        ret |= SetOjectIdValue(output, outSz, &idx,
            extExtKeyUsageAnyOid, sizeof(extExtKeyUsageAnyOid));
    }
    else {
        if (input & EXTKEYUSE_SERVER_AUTH)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageServerAuthOid, sizeof(extExtKeyUsageServerAuthOid));
        if (input & EXTKEYUSE_CLIENT_AUTH)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageClientAuthOid, sizeof(extExtKeyUsageClientAuthOid));
        if (input & EXTKEYUSE_CODESIGN)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageCodeSigningOid, sizeof(extExtKeyUsageCodeSigningOid));
        if (input & EXTKEYUSE_EMAILPROT)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageEmailProtectOid, sizeof(extExtKeyUsageEmailProtectOid));
        if (input & EXTKEYUSE_TIMESTAMP)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageTimestampOid, sizeof(extExtKeyUsageTimestampOid));
        if (input & EXTKEYUSE_OCSP_SIGN)
            ret |= SetOjectIdValue(output, outSz, &idx,
                extExtKeyUsageOcspSignOid, sizeof(extExtKeyUsageOcspSignOid));
    #ifdef WOLFSSL_EKU_OID
        /* iterate through OID values */
        if (input & EXTKEYUSE_USER) {
            int i, sz;
            for (i = 0; i < CTC_MAX_EKU_NB; i++) {
                sz = cert->extKeyUsageOIDSz[i];
                if (sz > 0) {
                    ret |= SetOjectIdValue(output, outSz, &idx,
                        cert->extKeyUsageOID[i], sz);
                }
            }
        }
    #endif /* WOLFSSL_EKU_OID */
    }
    if (ret != 0)
        return ASN_PARSE_E;

    /* Calculate Sizes */
    oidListSz = idx - totalSz;
    totalSz = idx - 2; /* exclude first seq/len (2) */

    /* 1. Seq + Total Len (2) */
    idx = SetSequence(totalSz, output);

    /* 2. Object ID (2) */
    XMEMCPY(&output[idx], extkeyusage_oid, sizeof(extkeyusage_oid));
    idx += sizeof(extkeyusage_oid);

    /* 3. Octet String (2) */
    idx += SetOctetString(totalSz - idx, &output[idx]);

    /* 4. Seq + OidListLen (2) */
    idx += SetSequence(oidListSz, &output[idx]);

    /* 5. Oid List (already set in-place above) */
    idx += oidListSz;

    (void)cert;
    return (int)idx;
}

#ifndef IGNORE_NETSCAPE_CERT_TYPE
static int SetNsCertType(Cert* cert, byte* output, word32 outSz, byte input)
{
    word32 idx;
    byte unusedBits = 0;
    byte nsCertType = input;
    word32 totalSz;
    word32 bitStrSz;
    const byte nscerttype_oid[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                    0x86, 0xF8, 0x42, 0x01, 0x01 };

    if (cert == NULL || output == NULL ||
            input == 0)
        return BAD_FUNC_ARG;

    totalSz = sizeof(nscerttype_oid);

    /* Get amount of lsb zero's */
    for (;(input & 1) == 0; input >>= 1)
        unusedBits++;

    /* 1 byte of NS Cert Type extension */
    bitStrSz = SetBitString(1, unusedBits, NULL) + 1;
    totalSz += SetOctetString(bitStrSz, NULL) + bitStrSz;

    if (SetSequence(totalSz, NULL) + totalSz > outSz)
        return BAD_FUNC_ARG;

    /* 1. Seq + Total Len */
    idx = SetSequence(totalSz, output);

    /* 2. Object ID */
    XMEMCPY(&output[idx], nscerttype_oid, sizeof(nscerttype_oid));
    idx += sizeof(nscerttype_oid);

    /* 3. Octet String */
    idx += SetOctetString(bitStrSz, &output[idx]);

    /* 4. Bit String */
    idx += SetBitString(1, unusedBits, &output[idx]);
    output[idx++] = nsCertType;

    return (int)idx;
}

#endif
static int SetCRLInfo(Cert* cert, byte* output, word32 outSz, byte* input,
                      int inSz)
{
    word32 idx;
    word32 totalSz;
    const byte crlinfo_oid[] = { 0x06, 0x03, 0x55, 0x1D, 0x1F };

    if (cert == NULL || output == NULL ||
            input == 0 || inSz <= 0)
        return BAD_FUNC_ARG;

    totalSz = (word32)sizeof(crlinfo_oid) + SetOctetString((word32)inSz, NULL) +
        (word32)inSz;

    if (SetSequence(totalSz, NULL) + totalSz > outSz)
        return BAD_FUNC_ARG;

    /* 1. Seq + Total Len */
    idx = SetSequence(totalSz, output);

    /* 2. Object ID */
    XMEMCPY(&output[idx], crlinfo_oid, sizeof(crlinfo_oid));
    idx += sizeof(crlinfo_oid);

    /* 3. Octet String */
    idx += SetOctetString((word32)inSz, &output[idx]);

    /* 4. CRL Info */
    XMEMCPY(&output[idx], input, (size_t)inSz);
    idx += (word32)inSz;

    return (int)idx;
}

static int SetCertificatePolicies(byte *output,
                                  word32 outputSz,
                                  char input[MAX_CERTPOL_NB][MAX_CERTPOL_SZ],
                                  word16 nb_certpol,
                                  void* heap)
{
    byte    oid[MAX_OID_SZ];
    byte    der_oid[MAX_CERTPOL_NB][MAX_OID_SZ];
    byte    out[MAX_CERTPOL_SZ];
    word32  oidSz;
    word32  outSz;
    word32  i = 0;
    word32  der_oidSz[MAX_CERTPOL_NB];
    int     ret;

    const byte certpol_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04 };
    const byte oid_oid[] = { 0x06 };

    if (output == NULL || input == NULL || nb_certpol > MAX_CERTPOL_NB)
        return BAD_FUNC_ARG;

    for (i = 0; i < nb_certpol; i++) {
        oidSz = sizeof(oid);
        XMEMSET(oid, 0, oidSz);

        ret = EncodePolicyOID(oid, &oidSz, input[i], heap);
        if (ret != 0)
            return ret;

        /* compute sequence value for the oid */
        ret = SetOidValue(der_oid[i], MAX_OID_SZ, oid_oid,
                          sizeof(oid_oid), oid, oidSz);
        if (ret <= 0)
            return ret;
        else
            der_oidSz[i] = (word32)ret;
    }

    /* concatenate oid, keep two byte for sequence/size of the created value */
    for (i = 0, outSz = 2; i < nb_certpol; i++) {
        XMEMCPY(out+outSz, der_oid[i], der_oidSz[i]);
        outSz += der_oidSz[i];
    }

    /* add sequence */
    ret = (int)SetSequence(outSz-2, out);
    if (ret <= 0)
        return ret;

    /* add Policy OID to compute final value */
    return SetOidValue(output, outputSz, certpol_oid, sizeof(certpol_oid),
                      out, outSz);
}

#endif
#ifdef WOLFSSL_ALT_NAMES
/* encode Alternative Names, return total bytes written */
static int SetAltNames(byte *output, word32 outSz,
        const byte *input, word32 length, int critical)
{
    byte san_len[1 + MAX_LENGTH_SZ];
    const byte san_oid[] = { 0x06, 0x03, 0x55, 0x1d, 0x11 };
    const byte san_crit[] = { 0x01, 0x01, 0xff };
    word32 seqSz, san_lenSz, idx = 0;

    if (output == NULL || input == NULL)
        return BAD_FUNC_ARG;

    if (outSz < length)
        return BUFFER_E;

    /* Octet String header */
    san_lenSz = SetOctetString(length, san_len);

    seqSz = length + (word32)sizeof(san_oid) + san_lenSz;
    if (critical)
        seqSz += sizeof(san_crit);
    /* Tag plus encoded length. */
    if (outSz < 1 + ASN_LEN_ENC_LEN(seqSz))
        return BUFFER_E;
    idx = SetSequence(seqSz, output);

    if (idx + seqSz > outSz)
        return BUFFER_E;

    /* put oid */
    XMEMCPY(output+idx, san_oid, sizeof(san_oid));
    idx += sizeof(san_oid);

    if (critical) {
        XMEMCPY(output+idx, san_crit, sizeof(san_crit));
        idx += sizeof(san_crit);
    }

    /* put octet header */
    XMEMCPY(output+idx, san_len, san_lenSz);
    idx += san_lenSz;

    /* put value */
    XMEMCPY(output+idx, input, length);
    idx += length;

    return (int)idx;
}

#endif
#endif
#if defined(WOLFSSL_CERT_GEN) || defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
static int EncodeName(EncodedName* name, const char* nameStr,
                    byte nameTag, byte type, byte emailTag, CertName* cname)
{
    word32 idx = 0;
    /* bottom up */
    byte firstLen[1 + MAX_LENGTH_SZ];
    byte secondLen[MAX_LENGTH_SZ];
    byte sequence[MAX_SEQ_SZ];
    byte set[MAX_SET_SZ];

    word32 strLen;
    word32 thisLen;
    word32 firstSz, secondSz, seqSz, setSz;

    if (nameStr == NULL) {
        name->used = 0;
        return 0;
    }

    thisLen = strLen = (word32)XSTRLEN(nameStr);
#ifdef WOLFSSL_CUSTOM_OID
    if (type == ASN_CUSTOM_NAME) {
        if (cname == NULL || cname->custom.oidSz == 0) {
            name->used = 0;
            return 0;
        }
        thisLen = strLen = (word32)cname->custom.valSz;
    }
#else
    (void)cname;
#endif

    if (strLen == 0) { /* no user data for this item */
        name->used = 0;
        return 0;
    }

    /* Restrict country code size */
    if (type == ASN_COUNTRY_NAME && strLen != CTC_COUNTRY_SIZE) {
        WOLFSSL_MSG("Country code size error");
        WOLFSSL_ERROR_VERBOSE(ASN_COUNTRY_SIZE_E);
        return ASN_COUNTRY_SIZE_E;
    }

    secondSz = SetLength(strLen, secondLen);
    thisLen += secondSz;
    switch (type) {
        case ASN_EMAIL_NAME: /* email */
            thisLen += (int)sizeof(attrEmailOid);
            firstSz  = (int)sizeof(attrEmailOid);
            break;
        case ASN_DOMAIN_COMPONENT:
            thisLen += (int)sizeof(dcOid);
            firstSz  = (int)sizeof(dcOid);
            break;
        case ASN_USER_ID:
            thisLen += (int)sizeof(uidOid);
            firstSz  = (int)sizeof(uidOid);
            break;
        case ASN_RFC822_MAILBOX:
            thisLen += (int)sizeof(rfc822Mlbx);
            firstSz  = (int)sizeof(rfc822Mlbx);
            break;
        case ASN_FAVOURITE_DRINK:
            thisLen += (int)sizeof(fvrtDrk);
            firstSz  = (int)sizeof(fvrtDrk);
            break;
    #ifdef WOLFSSL_CUSTOM_OID
        case ASN_CUSTOM_NAME:
            thisLen += cname->custom.oidSz;
            firstSz = cname->custom.oidSz;
            break;
    #endif
    #ifdef WOLFSSL_CERT_REQ
        case ASN_CONTENT_TYPE:
            thisLen += (int)sizeof(attrPkcs9ContentTypeOid);
            firstSz  = (int)sizeof(attrPkcs9ContentTypeOid);
            break;
    #endif
        default:
            thisLen += DN_OID_SZ;
            firstSz  = DN_OID_SZ;
    }
    thisLen++; /* id  type */
    firstSz  = (word32)SetObjectId((int)firstSz, firstLen);
    thisLen += firstSz;

    seqSz = SetSequence(thisLen, sequence);
    thisLen += seqSz;
    setSz = SetSet(thisLen, set);
    thisLen += setSz;

    if (thisLen > (int)sizeof(name->encoded)) {
        return BUFFER_E;
    }

    /* store it */
    idx = 0;
    /* set */
    XMEMCPY(name->encoded, set, setSz);
    idx += setSz;
    /* seq */
    XMEMCPY(name->encoded + idx, sequence, seqSz);
    idx += seqSz;
    /* asn object id */
    XMEMCPY(name->encoded + idx, firstLen, firstSz);
    idx += firstSz;
    switch (type) {
        case ASN_EMAIL_NAME:
            /* email joint id */
            XMEMCPY(name->encoded + idx, attrEmailOid, sizeof(attrEmailOid));
            idx += (int)sizeof(attrEmailOid);
            name->encoded[idx++] = emailTag;
            break;
        case ASN_DOMAIN_COMPONENT:
            XMEMCPY(name->encoded + idx, dcOid, sizeof(dcOid)-1);
            idx += (int)sizeof(dcOid)-1;
            /* id type */
            name->encoded[idx++] = type;
            /* str type */
            name->encoded[idx++] = nameTag;
            break;
        case ASN_USER_ID:
            XMEMCPY(name->encoded + idx, uidOid, sizeof(uidOid));
            idx += (int)sizeof(uidOid);
            /* str type */
            name->encoded[idx++] = nameTag;
            break;
        case ASN_RFC822_MAILBOX:
            XMEMCPY(name->encoded + idx, rfc822Mlbx, sizeof(rfc822Mlbx));
            idx += (int)sizeof(rfc822Mlbx);
            /* str type */
            name->encoded[idx++] = nameTag;
            break;
        case ASN_FAVOURITE_DRINK:
            XMEMCPY(name->encoded + idx, fvrtDrk, sizeof(fvrtDrk));
            idx += (int)sizeof(fvrtDrk);
            /* str type */
            name->encoded[idx++] = nameTag;
            break;
    #ifdef WOLFSSL_CUSTOM_OID
        case ASN_CUSTOM_NAME:
            XMEMCPY(name->encoded + idx, cname->custom.oid,
                    cname->custom.oidSz);
            idx += cname->custom.oidSz;
            /* str type */
            name->encoded[idx++] = nameTag;
            break;
    #endif
    #ifdef WOLFSSL_CERT_REQ
        case ASN_CONTENT_TYPE:
            XMEMCPY(name->encoded + idx, attrPkcs9ContentTypeOid,
                    sizeof(attrPkcs9ContentTypeOid));
            idx += (int)sizeof(attrPkcs9ContentTypeOid);
            /* str type */
            name->encoded[idx++] = nameTag;
            break;
    #endif
        default:
            name->encoded[idx++] = 0x55;
            name->encoded[idx++] = 0x04;
            /* id type */
            name->encoded[idx++] = type;
            /* str type */
            name->encoded[idx++] = nameTag;
    }
    /* second length */
    XMEMCPY(name->encoded + idx, secondLen, secondSz);
    idx += secondSz;
    /* str value */
    XMEMCPY(name->encoded + idx, nameStr, strLen);
    idx += strLen;

    name->type = type;
    name->totalLen = (int)idx;
    name->used = 1;

    return (int)idx;
}

#endif
#ifdef WOLFSSL_CERT_GEN
int SetNameEx(byte* output, word32 outputSz, CertName* name, void* heap)
{
    int ret;
    int i;
    word32 idx, totalBytes = 0;
    WC_DECLARE_VAR(names, EncodedName, NAME_ENTRIES, 0);
#ifdef WOLFSSL_MULTI_ATTRIB
    EncodedName addNames[CTC_MAX_ATTRIB];
    int j, type;
#endif

    if (output == NULL || name == NULL)
        return BAD_FUNC_ARG;

    if (outputSz < 3)
        return BUFFER_E;

    WC_ALLOC_VAR_EX(names, EncodedName, NAME_ENTRIES, NULL,
        DYNAMIC_TYPE_TMP_BUFFER, return MEMORY_E);

    for (i = 0; i < NAME_ENTRIES; i++) {
        const char* nameStr = GetOneCertName(name, i);

        ret = EncodeName(&names[i], nameStr, (byte)GetNameType(name, i),
                          GetCertNameId(i), ASN_IA5_STRING, name);
        if (ret < 0) {
            WC_FREE_VAR_EX(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            WOLFSSL_MSG("EncodeName failed");
            return BUFFER_E;
        }
        totalBytes += (word32)ret;
    }
#ifdef WOLFSSL_MULTI_ATTRIB
    for (i = 0; i < CTC_MAX_ATTRIB; i++) {
        if (name->name[i].sz > 0) {
            ret = EncodeName(&addNames[i], name->name[i].value,
                             (byte)name->name[i].type, (byte)name->name[i].id,
                        ASN_IA5_STRING, NULL);
            if (ret < 0) {
                WC_FREE_VAR_EX(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                WOLFSSL_MSG("EncodeName on multiple attributes failed");
                return BUFFER_E;
            }
            totalBytes += (word32)ret;
        }
        else {
            addNames[i].used = 0;
        }
    }
#endif /* WOLFSSL_MULTI_ATTRIB */

    /* header */
    idx = SetSequence(totalBytes, output);
    totalBytes += idx;
    if (totalBytes > WC_ASN_NAME_MAX) {
        WC_FREE_VAR_EX(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        WOLFSSL_MSG("Total Bytes is greater than WC_ASN_NAME_MAX");
        return BUFFER_E;
    }

    for (i = 0; i < NAME_ENTRIES; i++) {
    #ifdef WOLFSSL_MULTI_ATTRIB
        type = GetCertNameId(i);
        for (j = 0; j < CTC_MAX_ATTRIB; j++) {
            if (name->name[j].sz > 0 && type == name->name[j].id) {
                if (outputSz < idx + (word32)addNames[j].totalLen) {
                    WC_FREE_VAR_EX(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    WOLFSSL_MSG("Not enough space left for DC value");
                    return BUFFER_E;
                }

                XMEMCPY(output + idx, addNames[j].encoded,
                        (size_t)addNames[j].totalLen);
                idx += (word32)addNames[j].totalLen;
            }
        }
    #endif /* WOLFSSL_MULTI_ATTRIB */

        if (names[i].used) {
            if (outputSz < idx + (word32)names[i].totalLen) {
                WC_FREE_VAR_EX(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return BUFFER_E;
            }

            XMEMCPY(output + idx, names[i].encoded, (size_t)names[i].totalLen);
            idx += (word32)names[i].totalLen;
        }
    }

    WC_FREE_VAR_EX(names, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    (void)heap;

    return (int)totalBytes;
}

/* Set Date validity from now until now + daysValid
 * return size in bytes written to output, 0 on error */
/* TODO https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
 * "MUST always encode certificate validity dates through the year 2049 as
 *  UTCTime; certificate validity dates in 2050 or later MUST be encoded as
 *  GeneralizedTime." */
static int SetValidity(byte* output, int daysValid)
{
#ifndef NO_ASN_TIME
    byte before[MAX_DATE_SIZE];
    byte  after[MAX_DATE_SIZE];

    word32 beforeSz, afterSz, seqSz;

    time_t now;
    time_t then;
    struct tm* tmpTime;
    struct tm* expandedTime;
    struct tm localTime;

#if defined(NEED_TMP_TIME)
    /* for use with gmtime_r */
    struct tm tmpTimeStorage;
    tmpTime = &tmpTimeStorage;
#else
    tmpTime = NULL;
#endif
    (void)tmpTime;

    now = wc_Time(0);

    /* before now */
    before[0] = ASN_GENERALIZED_TIME;
    beforeSz = SetLength(ASN_GEN_TIME_SZ, before + 1) + 1;  /* gen tag */

    /* subtract 1 day of seconds for more compliance */
    then = now - 86400;
    expandedTime = XGMTIME(&then, tmpTime);
    if (ValidateGmtime(expandedTime)) {
        WOLFSSL_MSG("XGMTIME failed");
        return 0;   /* error */
    }
    localTime = *expandedTime;

    /* adjust */
    localTime.tm_year += 1900;
    localTime.tm_mon +=    1;

    SetTime(&localTime, before + beforeSz);
    beforeSz += ASN_GEN_TIME_SZ;

    after[0] = ASN_GENERALIZED_TIME;
    afterSz  = SetLength(ASN_GEN_TIME_SZ, after + 1) + 1;  /* gen tag */

    /* add daysValid of seconds */
    then = now + (daysValid * (time_t)86400);
    expandedTime = XGMTIME(&then, tmpTime);
    if (ValidateGmtime(expandedTime)) {
        WOLFSSL_MSG("XGMTIME failed");
        return 0;   /* error */
    }
    localTime = *expandedTime;

    /* adjust */
    localTime.tm_year += 1900;
    localTime.tm_mon  +=    1;

    SetTime(&localTime, after + afterSz);
    afterSz += ASN_GEN_TIME_SZ;

    /* headers and output */
    seqSz = SetSequence(beforeSz + afterSz, output);
    XMEMCPY(output + seqSz, before, beforeSz);
    XMEMCPY(output + seqSz + beforeSz, after, afterSz);

    return (int)(seqSz + beforeSz + afterSz);
#else
    (void)output;
    (void)daysValid;
    return NOT_COMPILED_IN;
#endif
}

/* encode info from cert into DER encoded format */
static int EncodeCert(Cert* cert, DerCert* der, RsaKey* rsaKey, ecc_key* eccKey,
                      WC_RNG* rng, DsaKey* dsaKey, ed25519_key* ed25519Key,
                      ed448_key* ed448Key, falcon_key* falconKey,
                      dilithium_key* dilithiumKey, SlhDsaKey* slhDsaKey)
{
    int ret;

    if (cert == NULL || der == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    /* make sure at least one key type is provided */
    if (rsaKey == NULL && eccKey == NULL && ed25519Key == NULL &&
        dsaKey == NULL && ed448Key == NULL && falconKey == NULL &&
        dilithiumKey == NULL && slhDsaKey == NULL) {
        return PUBLIC_KEY_E;
    }

    /* init */
    XMEMSET(der, 0, sizeof(DerCert));

    /* version */
    der->versionSz = SetMyVersion((word32)cert->version, der->version, TRUE);

    /* serial number (must be positive) */
    if (cert->serialSz == 0) {
        /* generate random serial */
        cert->serialSz = CTC_GEN_SERIAL_SZ;
        ret = wc_RNG_GenerateBlock(rng, cert->serial, (word32)cert->serialSz);
        if (ret != 0)
            return ret;
        /* Clear the top bit to avoid a negative value */
        cert->serial[0] &= 0x7f;
    }
    der->serialSz = SetSerialNumber(cert->serial, (word32)cert->serialSz,
                                    der->serial, sizeof(der->serial),
                                    CTC_SERIAL_SIZE);
    if (der->serialSz < 0)
        return der->serialSz;

    /* signature algo */
    der->sigAlgoSz = (int)SetAlgoID(cert->sigType, der->sigAlgo, oidSigType, 0);
    if (der->sigAlgoSz <= 0)
        return ALGO_ID_E;

    /* public key */
#ifndef NO_RSA
    if (cert->keyType == RSA_KEY) {
        if (rsaKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetRsaPublicKey(der->publicKey, rsaKey,
                                           sizeof(der->publicKey), 1);
    }
#endif

#ifdef HAVE_ECC
    if (cert->keyType == ECC_KEY) {
        if (eccKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetEccPublicKey(der->publicKey, eccKey,
                                           sizeof(der->publicKey), 1, 0);
    }
#endif

#if !defined(NO_DSA) && !defined(HAVE_SELFTEST)
    if (cert->keyType == DSA_KEY) {
        if (dsaKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = wc_SetDsaPublicKey(der->publicKey, dsaKey,
                                              sizeof(der->publicKey), 1);
    }
#endif

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
    if (cert->keyType == ED25519_KEY) {
        if (ed25519Key == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = wc_Ed25519PublicKeyToDer(ed25519Key, der->publicKey,
            (word32)sizeof(der->publicKey), 1);
    }
#endif

#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)
    if (cert->keyType == ED448_KEY) {
        if (ed448Key == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = wc_Ed448PublicKeyToDer(ed448Key, der->publicKey,
            (word32)sizeof(der->publicKey), 1);
    }
#endif

#if defined(HAVE_FALCON)
    if ((cert->keyType == FALCON_LEVEL1_KEY) ||
        (cert->keyType == FALCON_LEVEL5_KEY)) {
        if (falconKey == NULL)
            return PUBLIC_KEY_E;

        der->publicKeySz =
            wc_Falcon_PublicKeyToDer(falconKey, der->publicKey,
                                     (word32)sizeof(der->publicKey), 1);
    }
#endif /* HAVE_FALCON */
#if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_NO_ASN1)
    if ((cert->keyType == ML_DSA_LEVEL2_KEY) ||
        (cert->keyType == ML_DSA_LEVEL3_KEY) ||
        (cert->keyType == ML_DSA_LEVEL5_KEY)
    #ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
     || (cert->keyType == DILITHIUM_LEVEL2_KEY)
     || (cert->keyType == DILITHIUM_LEVEL3_KEY)
     || (cert->keyType == DILITHIUM_LEVEL5_KEY)
    #endif
        ) {
        if (dilithiumKey == NULL)
            return PUBLIC_KEY_E;

        der->publicKeySz =
            wc_Dilithium_PublicKeyToDer(dilithiumKey, der->publicKey,
                                     (word32)sizeof(der->publicKey), 1);
    }
#endif /* HAVE_DILITHIUM */
#if defined(WOLFSSL_HAVE_SLHDSA)
    if ((cert->keyType == SLH_DSA_SHAKE_128F_KEY) ||
        (cert->keyType == SLH_DSA_SHAKE_192F_KEY) ||
        (cert->keyType == SLH_DSA_SHAKE_256F_KEY) ||
        (cert->keyType == SLH_DSA_SHAKE_128S_KEY) ||
        (cert->keyType == SLH_DSA_SHAKE_192S_KEY) ||
        (cert->keyType == SLH_DSA_SHAKE_256S_KEY)
    #ifdef WOLFSSL_SLHDSA_SHA2
     || (cert->keyType == SLH_DSA_SHA2_128F_KEY) ||
        (cert->keyType == SLH_DSA_SHA2_192F_KEY) ||
        (cert->keyType == SLH_DSA_SHA2_256F_KEY) ||
        (cert->keyType == SLH_DSA_SHA2_128S_KEY) ||
        (cert->keyType == SLH_DSA_SHA2_192S_KEY) ||
        (cert->keyType == SLH_DSA_SHA2_256S_KEY)
    #endif
        ) {
        if (slhDsaKey == NULL)
            return PUBLIC_KEY_E;

        der->publicKeySz =
            wc_SlhDsaKey_PublicKeyToDer(slhDsaKey, der->publicKey,
                                      (word32)sizeof(der->publicKey), 1);
    }
#endif /* WOLFSSL_HAVE_SLHDSA */

    if (der->publicKeySz <= 0)
        return PUBLIC_KEY_E;

    der->validitySz = 0;
    /* copy date validity if already set in cert struct */
    if (cert->beforeDateSz && cert->afterDateSz) {
        der->validitySz = CopyValidity(der->validity, cert);
        if (der->validitySz <= 0)
            return DATE_E;
    }

    /* set date validity using daysValid if not set already */
    if (der->validitySz == 0) {
        der->validitySz = SetValidity(der->validity, cert->daysValid);
        if (der->validitySz <= 0)
            return DATE_E;
    }

    /* subject name */
#if defined(WOLFSSL_CERT_EXT) || defined(OPENSSL_EXTRA)
    if (XSTRLEN((const char*)cert->sbjRaw) > 0) {
        /* Use the raw subject */
        word32 idx;

        der->subjectSz = (int)min((word32)sizeof(der->subject),
                                  (word32)XSTRLEN((const char*)cert->sbjRaw));
        /* header */
        idx = SetSequence((word32)der->subjectSz, der->subject);
        if ((word32)der->subjectSz + idx > (word32)sizeof(der->subject)) {
            return SUBJECT_E;
        }

        XMEMCPY((char*)der->subject + idx, (const char*)cert->sbjRaw,
                (size_t)der->subjectSz);
        der->subjectSz += (int)idx;
    }
    else
#endif
    {
        /* Use the name structure */
        der->subjectSz = SetNameEx(der->subject, sizeof(der->subject),
                &cert->subject, cert->heap);
    }
    if (der->subjectSz <= 0)
        return SUBJECT_E;

    /* issuer name */
#if defined(WOLFSSL_CERT_EXT) || defined(OPENSSL_EXTRA)
    if (XSTRLEN((const char*)cert->issRaw) > 0) {
        /* Use the raw issuer */
        word32 idx;

        der->issuerSz = (int)min((word32)sizeof(der->issuer),
                                 (word32)XSTRLEN((const char*)cert->issRaw));

        /* header */
        idx = SetSequence((word32)der->issuerSz, der->issuer);
        if ((word32)der->issuerSz + idx > (word32)sizeof(der->issuer)) {
            return ISSUER_E;
        }

        XMEMCPY((char*)der->issuer + idx, (const char*)cert->issRaw,
                (size_t)der->issuerSz);
        der->issuerSz += (int)idx;
    }
    else
#endif
    {
        /* Use the name structure */
        der->issuerSz = SetNameEx(der->issuer, sizeof(der->issuer),
                cert->selfSigned ? &cert->subject : &cert->issuer, cert->heap);
    }
    if (der->issuerSz <= 0)
        return ISSUER_E;

    /* set the extensions */
    der->extensionsSz = 0;

    /* RFC 5280 : 4.2.1.9. Basic Constraints
     * The pathLenConstraint field is meaningful only if the CA boolean is
     * asserted and the key usage extension, if present, asserts the
     * keyCertSign bit */
    /* Set CA and path length */
    if ((cert->isCA) && (cert->pathLenSet)
#ifdef WOLFSSL_CERT_EXT
        && ((cert->keyUsage & KEYUSE_KEY_CERT_SIGN) || (!cert->keyUsage))
#endif
        ) {
        der->caSz = SetCaWithPathLen(der->ca, sizeof(der->ca), cert->pathLen);
        if (der->caSz <= 0)
            return CA_TRUE_E;

        der->extensionsSz += der->caSz;
    }
#ifdef WOLFSSL_ALLOW_ENCODING_CA_FALSE
    /* Set CA */
    else if (cert->isCaSet) {
        der->caSz = SetCaEx(der->ca, sizeof(der->ca), cert->isCA);
        if (der->caSz <= 0)
            return EXTENSIONS_E;

        der->extensionsSz += der->caSz;
    }
#endif
    /* Set CA true */
    else if (cert->isCA) {
        der->caSz = SetCa(der->ca, sizeof(der->ca));
        if (der->caSz <= 0)
            return CA_TRUE_E;

        der->extensionsSz += der->caSz;
    }
    /* Set Basic Constraint */
    else if (cert->basicConstSet) {
        der->caSz = SetBC(der->ca, sizeof(der->ca));
        if (der->caSz <= 0)
            return EXTENSIONS_E;

        der->extensionsSz += der->caSz;
    }
    else
        der->caSz = 0;

#ifdef WOLFSSL_ALT_NAMES
    /* Alternative Name */
    if (cert->altNamesSz) {
        der->altNamesSz = SetAltNames(der->altNames, sizeof(der->altNames),
                                      cert->altNames, (word32)cert->altNamesSz,
                                      cert->altNamesCrit);
        if (der->altNamesSz <= 0)
            return ALT_NAME_E;

        der->extensionsSz += der->altNamesSz;
    }
    else
        der->altNamesSz = 0;
#endif

#ifdef WOLFSSL_CERT_EXT
    /* SKID */
    if (cert->skidSz) {
        /* check the provided SKID size */
        if (cert->skidSz > (int)min(CTC_MAX_SKID_SIZE, sizeof(der->skid)))
            return SKID_E;

        /* Note: different skid buffers sizes for der (MAX_KID_SZ) and
            cert (CTC_MAX_SKID_SIZE). */
        der->skidSz = SetSKID(der->skid, sizeof(der->skid),
                              cert->skid, (word32)cert->skidSz);
        if (der->skidSz <= 0)
            return SKID_E;

        der->extensionsSz += der->skidSz;
    }
    else
        der->skidSz = 0;

    /* AKID */
    if (cert->akidSz) {
        /* check the provided AKID size */
        if ((
#ifdef WOLFSSL_AKID_NAME
             !cert->rawAkid &&
#endif
              cert->akidSz > (int)min(CTC_MAX_AKID_SIZE, sizeof(der->akid)))
#ifdef WOLFSSL_AKID_NAME
          || (cert->rawAkid && cert->akidSz > (int)sizeof(der->akid))
#endif
             )
            return AKID_E;

        der->akidSz = SetAKID(der->akid, sizeof(der->akid), cert->akid,
                              (word32)cert->akidSz,
#ifdef WOLFSSL_AKID_NAME
                              cert->rawAkid
#else
                              0
#endif
                              );
        if (der->akidSz <= 0)
            return AKID_E;

        der->extensionsSz += der->akidSz;
    }
    else
        der->akidSz = 0;

    /* Key Usage */
    if (cert->keyUsage != 0){
        der->keyUsageSz = SetKeyUsage(der->keyUsage, sizeof(der->keyUsage),
                                      cert->keyUsage);
        if (der->keyUsageSz <= 0)
            return KEYUSAGE_E;

        der->extensionsSz += der->keyUsageSz;
    }
    else
        der->keyUsageSz = 0;

    /* Extended Key Usage */
    if (cert->extKeyUsage != 0){
        der->extKeyUsageSz = SetExtKeyUsage(cert, der->extKeyUsage,
                                sizeof(der->extKeyUsage), cert->extKeyUsage);
        if (der->extKeyUsageSz <= 0)
            return EXTKEYUSAGE_E;

        der->extensionsSz += der->extKeyUsageSz;
    }
    else
        der->extKeyUsageSz = 0;

#ifndef IGNORE_NETSCAPE_CERT_TYPE
    /* Netscape Certificate Type */
    if (cert->nsCertType != 0) {
        der->nsCertTypeSz = SetNsCertType(cert, der->nsCertType,
                                sizeof(der->nsCertType), cert->nsCertType);
        if (der->nsCertTypeSz <= 0)
            return EXTENSIONS_E;

        der->extensionsSz += der->nsCertTypeSz;
    }
    else
        der->nsCertTypeSz = 0;
#endif

    if (cert->crlInfoSz > 0) {
        der->crlInfoSz = SetCRLInfo(cert, der->crlInfo, sizeof(der->crlInfo),
                                cert->crlInfo, cert->crlInfoSz);
        if (der->crlInfoSz <= 0)
            return EXTENSIONS_E;

        der->extensionsSz += der->crlInfoSz;
    }
    else
        der->crlInfoSz = 0;

    /* Certificate Policies */
    if (cert->certPoliciesNb != 0) {
        der->certPoliciesSz = SetCertificatePolicies(der->certPolicies,
                                                     sizeof(der->certPolicies),
                                                     cert->certPolicies,
                                                     cert->certPoliciesNb,
                                                     cert->heap);
        if (der->certPoliciesSz <= 0)
            return CERTPOLICIES_E;

        der->extensionsSz += der->certPoliciesSz;
    }
    else
        der->certPoliciesSz = 0;
#endif /* WOLFSSL_CERT_EXT */

#ifdef WOLFSSL_ACME_OID
    /* RFC 8737 id-pe-acmeIdentifier (TLS-ALPN-01 challenge cert).
     * Always critical=TRUE. */
    if (cert->acmeIdentifierSz == WC_SHA256_DIGEST_SIZE) {
        der->acmeIdSz = SetAcmeIdentifier(der->acmeId, sizeof(der->acmeId),
                                          cert->acmeIdentifier,
                                          (word32)cert->acmeIdentifierSz);
        if (der->acmeIdSz <= 0)
            return EXTENSIONS_E;

        der->extensionsSz += der->acmeIdSz;
    }
    else
        der->acmeIdSz = 0;
#endif

    /* put extensions */
    if (der->extensionsSz > 0) {

        /* put the start of extensions sequence (ID, Size) */
        der->extensionsSz = SetExtensionsHeader(der->extensions,
                                                sizeof(der->extensions),
                                                (word32)der->extensionsSz);
        if (der->extensionsSz <= 0)
            return EXTENSIONS_E;

        /* put CA */
        if (der->caSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->ca, der->caSz);
            if (ret == 0)
                return EXTENSIONS_E;
        }

#ifdef WOLFSSL_ALT_NAMES
        /* put Alternative Names */
        if (der->altNamesSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->altNames, der->altNamesSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif

#ifdef WOLFSSL_CERT_EXT
        /* put SKID */
        if (der->skidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->skid, der->skidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put AKID */
        if (der->akidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->akid, der->akidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put CRL Distribution Points */
        if (der->crlInfoSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->crlInfo, der->crlInfoSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put KeyUsage */
        if (der->keyUsageSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->keyUsage, der->keyUsageSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put ExtendedKeyUsage */
        if (der->extKeyUsageSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->extKeyUsage, der->extKeyUsageSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put Netscape Cert Type */
#ifndef IGNORE_NETSCAPE_CERT_TYPE
        if (der->nsCertTypeSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->nsCertType, der->nsCertTypeSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif

        /* put Certificate Policies */
        if (der->certPoliciesSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->certPolicies, der->certPoliciesSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif /* WOLFSSL_CERT_EXT */

#ifdef WOLFSSL_ACME_OID
        /* put ACME Identifier */
        if (der->acmeIdSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->acmeId, der->acmeIdSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif
    }

    der->total = der->versionSz + der->serialSz + der->sigAlgoSz +
        der->publicKeySz + der->validitySz + der->subjectSz + der->issuerSz +
        der->extensionsSz;

    return 0;
}


/* write DER encoded cert to buffer, size already checked */
static int WriteCertBody(DerCert* der, byte* buf)
{
    word32 idx;

    /* signed part header */
    idx = SetSequence((word32)der->total, buf);
    /* version */
    XMEMCPY(buf + idx, der->version, (size_t)der->versionSz);
    idx += (word32)der->versionSz;
    /* serial */
    XMEMCPY(buf + idx, der->serial, (size_t)der->serialSz);
    idx += (word32)der->serialSz;
    /* sig algo */
    XMEMCPY(buf + idx, der->sigAlgo, (size_t)der->sigAlgoSz);
    idx += (word32)der->sigAlgoSz;
    /* issuer */
    XMEMCPY(buf + idx, der->issuer, (size_t)der->issuerSz);
    idx += (word32)der->issuerSz;
    /* validity */
    XMEMCPY(buf + idx, der->validity, (size_t)der->validitySz);
    idx += (word32)der->validitySz;
    /* subject */
    XMEMCPY(buf + idx, der->subject, (size_t)der->subjectSz);
    idx += (word32)der->subjectSz;
    /* public key */
    XMEMCPY(buf + idx, der->publicKey, (size_t)der->publicKeySz);
    idx += (word32)der->publicKeySz;
    if (der->extensionsSz) {
        /* extensions */
        XMEMCPY(buf + idx, der->extensions,
                min((word32)der->extensionsSz,
                    (word32)sizeof(der->extensions)));
        idx += (word32)der->extensionsSz;
    }

    return (int)idx;
}

int AddSignature(byte* buf, int bodySz, const byte* sig, int sigSz,
                        int sigAlgoType)
{
    byte seq[MAX_SEQ_SZ];
    word32 idx, seqSz;

    if ((bodySz < 0) || (sigSz < 0))
        return BUFFER_E;

    idx = (word32)bodySz;

    /* algo */
    idx += SetAlgoID(sigAlgoType, buf ? buf + idx : NULL, oidSigType, 0);
    /* bit string */
    idx += SetBitString((word32)sigSz, 0, buf ? buf + idx : NULL);
    /* signature */
    if (buf)
        XMEMCPY(buf + idx, sig, (size_t)sigSz);
    idx += (word32)sigSz;

    /* make room for overall header */
    seqSz = SetSequence(idx, seq);
    if (buf) {
        XMEMMOVE(buf + seqSz, buf, idx);
        XMEMCPY(buf, seq, seqSz);
    }

    return (int)(idx + seqSz);
}

static int MakeAnyCert(Cert* cert, byte* derBuffer, word32 derSz,
                       RsaKey* rsaKey, ecc_key* eccKey, WC_RNG* rng,
                       DsaKey* dsaKey, ed25519_key* ed25519Key,
                       ed448_key* ed448Key, falcon_key* falconKey,
                       dilithium_key* dilithiumKey, SlhDsaKey* slhDsaKey)
{
    int ret;
    WC_DECLARE_VAR(der, DerCert, 1, 0);

    if (derBuffer == NULL)
        return BAD_FUNC_ARG;

    if (eccKey)
        cert->keyType = ECC_KEY;
    else if (rsaKey)
        cert->keyType = RSA_KEY;
    else if (dsaKey)
        cert->keyType = DSA_KEY;
    else if (ed25519Key)
        cert->keyType = ED25519_KEY;
    else if (ed448Key)
        cert->keyType = ED448_KEY;
#ifdef HAVE_FALCON
    else if ((falconKey != NULL) && (falconKey->level == 1))
        cert->keyType = FALCON_LEVEL1_KEY;
    else if ((falconKey != NULL) && (falconKey->level == 5))
        cert->keyType = FALCON_LEVEL5_KEY;
#endif /* HAVE_FALCON */
#ifdef HAVE_DILITHIUM
    #ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_44_DRAFT)) {
        cert->keyType = DILITHIUM_LEVEL2_KEY;
    }
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_65_DRAFT)) {
        cert->keyType = DILITHIUM_LEVEL3_KEY;
    }
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_87_DRAFT)) {
        cert->keyType = DILITHIUM_LEVEL5_KEY;
    }
    #endif
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_44)) {
        cert->keyType = ML_DSA_LEVEL2_KEY;
    }
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_65)) {
        cert->keyType = ML_DSA_LEVEL3_KEY;
    }
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_87)) {
        cert->keyType = ML_DSA_LEVEL5_KEY;
    }
#endif /* HAVE_DILITHIUM */
#ifdef WOLFSSL_HAVE_SLHDSA
    else if ((slhDsaKey != NULL) && (slhDsaKey->params != NULL) &&
             (SlhDsaParamToKeyType(slhDsaKey->params->param) != 0)) {
        cert->keyType = SlhDsaParamToKeyType(slhDsaKey->params->param);
    }
#endif /* WOLFSSL_HAVE_SLHDSA */
    else
        return BAD_FUNC_ARG;

    WC_ALLOC_VAR_EX(der, DerCert, 1, cert->heap, DYNAMIC_TYPE_TMP_BUFFER,
        return MEMORY_E);

    ret = EncodeCert(cert, der, rsaKey, eccKey, rng, dsaKey, ed25519Key,
                     ed448Key, falconKey, dilithiumKey, slhDsaKey);
    if (ret == 0) {
        if (der->total + MAX_SEQ_SZ * 2 > (int)derSz)
            ret = BUFFER_E;
        else
            ret = cert->bodySz = WriteCertBody(der, derBuffer);
    }

    WC_FREE_VAR_EX(der, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#ifdef WOLFSSL_CERT_REQ
/* return size of data set on success
 * if getting size only then attr and oid should be NULL
 */
static word32 SetReqAttribSingle(byte* output, word32* idx, char* attr,
        word32 attrSz, const byte* oid, word32 oidSz, byte printable,
        word32 extSz)
{
    word32 totalSz = 0;
    word32 seqSz = 0;
    word32 setSz = 0;
    word32 strSz = 0;
    byte seq[MAX_SEQ_SZ];
    byte set[MAX_SET_SZ];
    byte str[MAX_PRSTR_SZ];

    totalSz = (word32)SetObjectId((int)oidSz, NULL);
    totalSz += oidSz;
    if (extSz > 0) {
        totalSz += setSz = SetSet(extSz, set);
        totalSz += seqSz = SetSequence(totalSz + extSz, seq);
        totalSz += extSz;
    }
    else {
        if (printable) {
            strSz = SetPrintableString(attrSz, str);
            totalSz += strSz;
        }
        else {
            totalSz += strSz = SetUTF8String(attrSz, str);
        }
        totalSz += setSz = SetSet(strSz + attrSz, set);
        totalSz += seqSz = SetSequence(totalSz + attrSz, seq);
        totalSz += attrSz;
    }

    if (oid) {
        XMEMCPY(&output[*idx], seq, seqSz);
        *idx += seqSz;
        *idx += (word32)SetObjectId((int)oidSz, output + *idx);
        XMEMCPY(&output[*idx], oid, oidSz);
        *idx += oidSz;
        XMEMCPY(&output[*idx], set, setSz);
        *idx += setSz;
        if (strSz > 0) {
            XMEMCPY(&output[*idx], str, strSz);
            *idx += strSz;
            if (attrSz > 0) {
                XMEMCPY(&output[*idx], attr, attrSz);
                *idx += attrSz;
            }
        }
    }
    return totalSz;
}



static int SetReqAttrib(byte* output, Cert* cert, word32 extSz)
{
    word32 sz      = 0; /* overall size */
    word32 setSz   = 0;

    output[0] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED;
    sz++;

    if (cert->challengePw[0]) {
        setSz += SetReqAttribSingle(output, &sz, NULL,
                (word32)XSTRLEN(cert->challengePw), NULL,
                sizeof(attrChallengePasswordOid),
                (byte)cert->challengePwPrintableString, 0);
    }

    if (cert->unstructuredName[0]) {
        setSz += SetReqAttribSingle(output, &sz, NULL,
                (word32)XSTRLEN(cert->unstructuredName), NULL,
                sizeof(attrUnstructuredNameOid), 1, 0);
    }

    if (extSz) {
        setSz += SetReqAttribSingle(output, &sz, NULL, 0, NULL,
                sizeof(attrExtensionRequestOid), 1, extSz);
    }

    /* Put the pieces together. */
    sz += SetLength(setSz, &output[sz]);
    if (sz + setSz - extSz > MAX_ATTRIB_SZ) {
        WOLFSSL_MSG("Attribute Buffer is not big enough!");
        return REQ_ATTRIBUTE_E;
    }

    if (cert->challengePw[0]) {
        SetReqAttribSingle(output, &sz, cert->challengePw,
                (word32)XSTRLEN(cert->challengePw),
                &attrChallengePasswordOid[0],
                sizeof(attrChallengePasswordOid),
                (byte)cert->challengePwPrintableString, 0);
    }

    if (cert->unstructuredName[0]) {
        SetReqAttribSingle(output, &sz, cert->unstructuredName,
                (word32)XSTRLEN(cert->unstructuredName),
                &attrUnstructuredNameOid[0],
                sizeof(attrUnstructuredNameOid), 1, 0);
    }

    if (extSz) {
        SetReqAttribSingle(output, &sz, NULL, 0, &attrExtensionRequestOid[0],
                sizeof(attrExtensionRequestOid), 1, extSz);
        /* The actual extension data will be tacked onto the output later. */
    }

    return (int)sz;
}

#ifdef WOLFSSL_CUSTOM_OID
/* encode a custom oid and value */
static int SetCustomObjectId(Cert* cert, byte* output, word32 outSz,
    CertOidField* custom)
{
    int idx = 0, cust_lenSz, cust_oidSz;

    if (cert == NULL || output == NULL || custom == NULL) {
        return BAD_FUNC_ARG;
    }
    if (custom->oid == NULL || custom->oidSz <= 0) {
        return 0; /* none set */
    }

    /* Octet String header */
    cust_lenSz = SetOctetString(custom->valSz, NULL);
    cust_oidSz = SetObjectId(custom->oidSz, NULL);

    /* check for output buffer room */
    if ((word32)(custom->valSz + custom->oidSz + cust_lenSz + cust_oidSz) >
                                                                        outSz) {
        return BUFFER_E;
    }

    /* put sequence with total */
    idx = SetSequence(custom->valSz + custom->oidSz + cust_lenSz + cust_oidSz,
                      output);

    /* put oid header */
    idx += SetObjectId(custom->oidSz, output+idx);
    XMEMCPY(output+idx, custom->oid, custom->oidSz);
    idx += custom->oidSz;

    /* put value */
    idx += SetOctetString(custom->valSz, output+idx);
    XMEMCPY(output+idx, custom->val, custom->valSz);
    idx += custom->valSz;

    return idx;
}
#endif /* WOLFSSL_CUSTOM_OID */


/* encode info from cert into DER encoded format */
static int EncodeCertReq(Cert* cert, DerCert* der, RsaKey* rsaKey,
                         DsaKey* dsaKey, ecc_key* eccKey,
                         ed25519_key* ed25519Key, ed448_key* ed448Key,
                         falcon_key* falconKey, dilithium_key* dilithiumKey,
                         SlhDsaKey* slhDsaKey)
{
    int ret;

    (void)eccKey;
    (void)ed25519Key;
    (void)ed448Key;
    (void)falconKey;
    (void)dilithiumKey;
    (void)slhDsaKey;

    if (cert == NULL || der == NULL)
        return BAD_FUNC_ARG;

    if (rsaKey == NULL && eccKey == NULL && ed25519Key == NULL &&
        dsaKey == NULL && ed448Key == NULL && falconKey == NULL &&
        dilithiumKey == NULL && slhDsaKey == NULL) {
        return PUBLIC_KEY_E;
    }

    /* init */
    XMEMSET(der, 0, sizeof(DerCert));

    /* version */
    der->versionSz = SetMyVersion((word32)cert->version, der->version, FALSE);

    /* subject name */
#if defined(WOLFSSL_CERT_EXT) || defined(OPENSSL_EXTRA)
    if (XSTRLEN((const char*)cert->sbjRaw) > 0) {
        /* Use the raw subject */
        int idx;

        der->subjectSz = (int)min(sizeof(der->subject),
                (word32)XSTRLEN((const char*)cert->sbjRaw));
        /* header */
        idx = (int)SetSequence((word32)der->subjectSz, der->subject);
        if (der->subjectSz + idx > (int)sizeof(der->subject)) {
            return SUBJECT_E;
        }

        XMEMCPY((char*)der->subject + idx, (const char*)cert->sbjRaw,
                (size_t)der->subjectSz);
        der->subjectSz += idx;
    }
    else
#endif
    {
        der->subjectSz = SetNameEx(der->subject, sizeof(der->subject),
                &cert->subject, cert->heap);
    }
    if (der->subjectSz <= 0)
        return SUBJECT_E;

    /* public key */
#ifndef NO_RSA
    if (cert->keyType == RSA_KEY) {
        if (rsaKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetRsaPublicKey(der->publicKey, rsaKey,
                                           sizeof(der->publicKey), 1);
    }
#endif

#if !defined(NO_DSA) && !defined(HAVE_SELFTEST)
    if (cert->keyType == DSA_KEY) {
        if (dsaKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = wc_SetDsaPublicKey(der->publicKey, dsaKey,
                                           sizeof(der->publicKey), 1);
    }
#endif

#ifdef HAVE_ECC
    if (cert->keyType == ECC_KEY) {
        if (eccKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = SetEccPublicKey(der->publicKey, eccKey,
                                           sizeof(der->publicKey), 1, 0);
    }
#endif

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
    if (cert->keyType == ED25519_KEY) {
        if (ed25519Key == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = wc_Ed25519PublicKeyToDer(ed25519Key, der->publicKey,
            (word32)sizeof(der->publicKey), 1);
    }
#endif

#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)
    if (cert->keyType == ED448_KEY) {
        if (ed448Key == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = wc_Ed448PublicKeyToDer(ed448Key, der->publicKey,
            (word32)sizeof(der->publicKey), 1);
    }
#endif
#if defined(HAVE_FALCON)
    if ((cert->keyType == FALCON_LEVEL1_KEY) ||
        (cert->keyType == FALCON_LEVEL5_KEY)) {
        if (falconKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = wc_Falcon_PublicKeyToDer(falconKey,
            der->publicKey, (word32)sizeof(der->publicKey), 1);
    }
#endif
#if defined(HAVE_DILITHIUM) && !defined(WOLFSSL_DILITHIUM_NO_ASN1)
    if ((cert->keyType == ML_DSA_LEVEL2_KEY) ||
        (cert->keyType == ML_DSA_LEVEL3_KEY) ||
        (cert->keyType == ML_DSA_LEVEL5_KEY)
    #ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
     || (cert->keyType == DILITHIUM_LEVEL2_KEY)
     || (cert->keyType == DILITHIUM_LEVEL3_KEY)
     || (cert->keyType == DILITHIUM_LEVEL5_KEY)
   #endif
        ) {
        if (dilithiumKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = wc_Dilithium_PublicKeyToDer(dilithiumKey,
            der->publicKey, (word32)sizeof(der->publicKey), 1);
    }
#endif
#if defined(WOLFSSL_HAVE_SLHDSA)
    if ((cert->keyType == SLH_DSA_SHAKE_128F_KEY) ||
        (cert->keyType == SLH_DSA_SHAKE_192F_KEY) ||
        (cert->keyType == SLH_DSA_SHAKE_256F_KEY) ||
        (cert->keyType == SLH_DSA_SHAKE_128S_KEY) ||
        (cert->keyType == SLH_DSA_SHAKE_192S_KEY) ||
        (cert->keyType == SLH_DSA_SHAKE_256S_KEY)
    #ifdef WOLFSSL_SLHDSA_SHA2
     || (cert->keyType == SLH_DSA_SHA2_128F_KEY) ||
        (cert->keyType == SLH_DSA_SHA2_192F_KEY) ||
        (cert->keyType == SLH_DSA_SHA2_256F_KEY) ||
        (cert->keyType == SLH_DSA_SHA2_128S_KEY) ||
        (cert->keyType == SLH_DSA_SHA2_192S_KEY) ||
        (cert->keyType == SLH_DSA_SHA2_256S_KEY)
    #endif
        ) {
        if (slhDsaKey == NULL)
            return PUBLIC_KEY_E;
        der->publicKeySz = wc_SlhDsaKey_PublicKeyToDer(slhDsaKey,
            der->publicKey, (word32)sizeof(der->publicKey), 1);
    }
#endif

    if (der->publicKeySz <= 0)
        return PUBLIC_KEY_E;

    /* set the extensions */
    der->extensionsSz = 0;

    /* RFC 5280 : 4.2.1.9. Basic Constraints
     * The pathLenConstraint field is meaningful only if the CA boolean is
     * asserted and the key usage extension, if present, asserts the
     * keyCertSign bit */
    /* Set CA and path length */
    if ((cert->isCA) && (cert->pathLenSet)
#ifdef WOLFSSL_CERT_EXT
        && ((cert->keyUsage & KEYUSE_KEY_CERT_SIGN) || (!cert->keyUsage))
#endif
        ) {
        der->caSz = SetCaWithPathLen(der->ca, sizeof(der->ca), cert->pathLen);
        if (der->caSz <= 0)
            return CA_TRUE_E;

        der->extensionsSz += der->caSz;
    }
#ifdef WOLFSSL_ALLOW_ENCODING_CA_FALSE
    /* Set CA */
    else if (cert->isCaSet) {
        der->caSz = SetCaEx(der->ca, sizeof(der->ca), cert->isCA);
        if (der->caSz <= 0)
            return EXTENSIONS_E;

        der->extensionsSz += der->caSz;
    }
#endif
    /* Set CA true */
    else if (cert->isCA) {
        der->caSz = SetCa(der->ca, sizeof(der->ca));
        if (der->caSz <= 0)
            return CA_TRUE_E;

        der->extensionsSz += der->caSz;
    }
    /* Set Basic Constraint */
    else if (cert->basicConstSet) {
        der->caSz = SetBC(der->ca, sizeof(der->ca));
        if (der->caSz <= 0)
            return EXTENSIONS_E;

        der->extensionsSz += der->caSz;
    }
    else
        der->caSz = 0;

#ifdef WOLFSSL_ALT_NAMES
    /* Alternative Name */
    if (cert->altNamesSz) {
        der->altNamesSz = SetAltNames(der->altNames, sizeof(der->altNames),
                                      cert->altNames, (word32)cert->altNamesSz,
                                      cert->altNamesCrit);
        if (der->altNamesSz <= 0)
            return ALT_NAME_E;

        der->extensionsSz += der->altNamesSz;
    }
    else
        der->altNamesSz = 0;
#endif

#ifdef WOLFSSL_CERT_EXT
    /* SKID */
    if (cert->skidSz) {
        /* check the provided SKID size */
        if (cert->skidSz > (int)min(CTC_MAX_SKID_SIZE, sizeof(der->skid)))
            return SKID_E;

        der->skidSz = SetSKID(der->skid, sizeof(der->skid),
                              cert->skid, (word32)cert->skidSz);
        if (der->skidSz <= 0)
            return SKID_E;

        der->extensionsSz += der->skidSz;
    }
    else
        der->skidSz = 0;

    /* Key Usage */
    if (cert->keyUsage != 0) {
        der->keyUsageSz = SetKeyUsage(der->keyUsage, sizeof(der->keyUsage),
                                      cert->keyUsage);
        if (der->keyUsageSz <= 0)
            return KEYUSAGE_E;

        der->extensionsSz += der->keyUsageSz;
    }
    else
        der->keyUsageSz = 0;

    /* Extended Key Usage */
    if (cert->extKeyUsage != 0) {
        der->extKeyUsageSz = SetExtKeyUsage(cert, der->extKeyUsage,
                                sizeof(der->extKeyUsage), cert->extKeyUsage);
        if (der->extKeyUsageSz <= 0)
            return EXTKEYUSAGE_E;

        der->extensionsSz += der->extKeyUsageSz;
    }
    else
        der->extKeyUsageSz = 0;

#endif /* WOLFSSL_CERT_EXT */

#ifdef WOLFSSL_CUSTOM_OID
    /* encode a custom oid and value */
    /* zero returns, means none set */
    ret = SetCustomObjectId(cert, der->extCustom,
        sizeof(der->extCustom), &cert->extCustom);
    if (ret < 0)
        return ret;
    der->extCustomSz = ret;
    der->extensionsSz += der->extCustomSz;
#endif

    /* put extensions */
    if (der->extensionsSz > 0) {
        /* put the start of sequence (ID, Size) */
        der->extensionsSz = (int)SetSequence((word32)der->extensionsSz,
                                             der->extensions);
        if (der->extensionsSz <= 0)
            return EXTENSIONS_E;

        /* put CA */
        if (der->caSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->ca, der->caSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

#ifdef WOLFSSL_ALT_NAMES
        /* put Alternative Names */
        if (der->altNamesSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->altNames, der->altNamesSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
#endif

#ifdef WOLFSSL_CERT_EXT
        /* put SKID */
        if (der->skidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->skid, der->skidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put AKID */
        if (der->akidSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->akid, der->akidSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put KeyUsage */
        if (der->keyUsageSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->keyUsage, der->keyUsageSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

        /* put ExtendedKeyUsage */
        if (der->extKeyUsageSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->extKeyUsage, der->extKeyUsageSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }

    #ifdef WOLFSSL_CUSTOM_OID
        if (der->extCustomSz) {
            ret = SetExtensions(der->extensions, sizeof(der->extensions),
                                &der->extensionsSz,
                                der->extCustom, der->extCustomSz);
            if (ret <= 0)
                return EXTENSIONS_E;
        }
    #endif
#endif /* WOLFSSL_CERT_EXT */
    }

    der->attribSz = SetReqAttrib(der->attrib, cert, (word32)der->extensionsSz);
    if (der->attribSz <= 0)
        return REQ_ATTRIBUTE_E;

    der->total = der->versionSz + der->subjectSz + der->publicKeySz +
        der->extensionsSz + der->attribSz;

    return 0;
}


/* write DER encoded cert req to buffer, size already checked */
static int WriteCertReqBody(DerCert* der, byte* buf)
{
    int idx;

    /* signed part header */
    idx = (int)SetSequence((word32)der->total, buf);
    /* version */
    if (buf)
        XMEMCPY(buf + idx, der->version, (size_t)der->versionSz);
    idx += der->versionSz;
    /* subject */
    if (buf)
        XMEMCPY(buf + idx, der->subject, (size_t)der->subjectSz);
    idx += der->subjectSz;
    /* public key */
    if (buf)
        XMEMCPY(buf + idx, der->publicKey, (size_t)der->publicKeySz);
    idx += der->publicKeySz;
    /* attributes */
    if (buf)
        XMEMCPY(buf + idx, der->attrib, (size_t)der->attribSz);
    idx += der->attribSz;
    /* extensions */
    if (der->extensionsSz) {
        if (buf)
            XMEMCPY(buf + idx, der->extensions, min((word32)der->extensionsSz,
                                               sizeof(der->extensions)));
        idx += der->extensionsSz;
    }

    return idx;
}

static int MakeCertReq(Cert* cert, byte* derBuffer, word32 derSz,
                   RsaKey* rsaKey, DsaKey* dsaKey, ecc_key* eccKey,
                   ed25519_key* ed25519Key, ed448_key* ed448Key,
                   falcon_key* falconKey, dilithium_key* dilithiumKey,
                   SlhDsaKey* slhDsaKey)
{
    int ret;
    WC_DECLARE_VAR(der, DerCert, 1, 0);

    if (eccKey)
        cert->keyType = ECC_KEY;
    else if (rsaKey)
        cert->keyType = RSA_KEY;
    else if (dsaKey)
        cert->keyType = DSA_KEY;
    else if (ed25519Key)
        cert->keyType = ED25519_KEY;
    else if (ed448Key)
        cert->keyType = ED448_KEY;
#ifdef HAVE_FALCON
    else if ((falconKey != NULL) && (falconKey->level == 1))
        cert->keyType = FALCON_LEVEL1_KEY;
    else if ((falconKey != NULL) && (falconKey->level == 5))
        cert->keyType = FALCON_LEVEL5_KEY;
#endif /* HAVE_FALCON */
#ifdef HAVE_DILITHIUM
    #ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_44_DRAFT)) {
        cert->keyType = DILITHIUM_LEVEL2_KEY;
    }
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_65_DRAFT)) {
        cert->keyType = DILITHIUM_LEVEL3_KEY;
    }
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_87_DRAFT)) {
        cert->keyType = DILITHIUM_LEVEL5_KEY;
    }
    #endif
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_44)) {
        cert->keyType = ML_DSA_LEVEL2_KEY;
    }
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_65)) {
        cert->keyType = ML_DSA_LEVEL3_KEY;
    }
    else if ((dilithiumKey != NULL) &&
                (dilithiumKey->params->level == WC_ML_DSA_87)) {
        cert->keyType = ML_DSA_LEVEL5_KEY;
    }
#endif /* HAVE_DILITHIUM */
#ifdef WOLFSSL_HAVE_SLHDSA
    else if ((slhDsaKey != NULL) && (slhDsaKey->params != NULL) &&
             (SlhDsaParamToKeyType(slhDsaKey->params->param) != 0)) {
        cert->keyType = SlhDsaParamToKeyType(slhDsaKey->params->param);
    }
#endif /* WOLFSSL_HAVE_SLHDSA */
    else
        return BAD_FUNC_ARG;

    WC_ALLOC_VAR_EX(der, DerCert, 1, cert->heap, DYNAMIC_TYPE_TMP_BUFFER,
        return MEMORY_E);

    ret = EncodeCertReq(cert, der, rsaKey, dsaKey, eccKey, ed25519Key, ed448Key,
                        falconKey, dilithiumKey, slhDsaKey);

    if (ret == 0) {
        if (der->total + MAX_SEQ_SZ * 2 > (int)derSz)
            ret = BUFFER_E;
        else
            ret = cert->bodySz = WriteCertReqBody(der, derBuffer);
    }

    WC_FREE_VAR_EX(der, cert->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#endif
#endif
#endif
#if !defined(NO_DH) && (defined(WOLFSSL_QT) || defined(OPENSSL_ALL))
int StoreDHparams(byte* out, word32* outLen, mp_int* p, mp_int* g)
{
    word32 idx = 0;
    word32 total;

    WOLFSSL_ENTER("StoreDHparams");

    if (out == NULL) {
        WOLFSSL_MSG("Null buffer error");
        return BUFFER_E;
    }

    /* determine size */
    /* integer - g */
    idx = SetASNIntMP(g, -1, NULL);
    /* integer - p */
    idx += SetASNIntMP(p, -1, NULL);
    total = idx;
     /* sequence */
    idx += SetSequence(idx, NULL);

    /* make sure output fits in buffer */
    if (idx > *outLen) {
        return BUFFER_E;
    }

    /* write DH parameters */
    /* sequence - for P and G only */
    idx = SetSequence(total, out);
    /* integer - p */
    idx += SetASNIntMP(p, -1, out + idx);
    /* integer - g */
    idx += SetASNIntMP(g, -1, out + idx);
    *outLen = idx;

    return 0;
}

#endif
#if defined(HAVE_ECC) || !defined(NO_DSA)
int StoreECC_DSA_Sig(byte* out, word32* outLen, mp_int* r, mp_int* s)
{
    word32 idx = 0;
    int    rSz;                           /* encoding size */
    int    sSz;
    int    headerSz = 4;   /* 2*ASN_TAG + 2*LEN(ENUM) */

    /* If the leading bit on the INTEGER is a 1, add a leading zero */
    int rLeadingZero = mp_leading_bit(r);
    int sLeadingZero = mp_leading_bit(s);
    int rLen = mp_unsigned_bin_size(r);   /* big int size */
    int sLen = mp_unsigned_bin_size(s);

    if (*outLen < (word32)((rLen + rLeadingZero + sLen + sLeadingZero +
            headerSz + 2)))  /* SEQ_TAG + LEN(ENUM) */
        return BUFFER_E;

    idx = SetSequence((word32)(rLen + rLeadingZero + sLen + sLeadingZero +
        headerSz), out);

    /* store r */
    rSz = SetASNIntMP(r, (int)(*outLen - idx), &out[idx]);
    if (rSz < 0)
        return rSz;
    idx += (word32)rSz;

    /* store s */
    sSz = SetASNIntMP(s, (int)(*outLen - idx), &out[idx]);
    if (sSz < 0)
        return sSz;
    idx += (word32)sSz;

    *outLen = idx;

    return 0;
}

/* determine if leading bit is set */
static word32 is_leading_bit_set(const byte* input, word32 sz)
{
    byte c = 0;
    if (sz > 0)
        c = input[0];
    return (c & 0x80) != 0;
}
static word32 trim_leading_zeros(const byte** input, word32 sz)
{
    int i;
    word32 leadingZeroCount = 0;
    const byte* tmp = *input;
    for (i=0; i<(int)sz; i++) {
        if (tmp[i] != 0)
            break;
        leadingZeroCount++;
    }
    /* catch all zero case */
    if (sz > 0 && leadingZeroCount == sz) {
        leadingZeroCount--;
    }
    *input += leadingZeroCount;
    sz -= leadingZeroCount;
    return sz;
}

int StoreECC_DSA_Sig_Bin(byte* out, word32* outLen, const byte* r, word32 rLen,
    const byte* s, word32 sLen)
{
    int ret;
    word32 idx;
    word32 headerSz = 4;   /* 2*ASN_TAG + 2*LEN(ENUM) */
    word32 rAddLeadZero, sAddLeadZero;

    if ((out == NULL) || (outLen == NULL) || (r == NULL) || (s == NULL))
        return BAD_FUNC_ARG;

    /* Trim leading zeros */
    rLen = trim_leading_zeros(&r, rLen);
    sLen = trim_leading_zeros(&s, sLen);
    /* If the leading bit on the INTEGER is a 1, add a leading zero */
    /* Add leading zero if MSB is set */
    rAddLeadZero = is_leading_bit_set(r, rLen);
    sAddLeadZero = is_leading_bit_set(s, sLen);

    if (*outLen < (rLen + rAddLeadZero + sLen + sAddLeadZero +
                   headerSz + 2))  /* SEQ_TAG + LEN(ENUM) */
        return BUFFER_E;

    idx = SetSequence(rLen+rAddLeadZero + sLen+sAddLeadZero + headerSz, out);

    /* store r */
    ret = SetASNInt((int)rLen, (byte)(rAddLeadZero ? 0x80U : 0x00U), &out[idx]);
    if (ret < 0)
        return ret;
    idx += (word32)ret;
    XMEMCPY(&out[idx], r, rLen);
    idx += rLen;

    /* store s */
    ret = SetASNInt((int)sLen, (byte)(sAddLeadZero ? 0x80U : 0x00U), &out[idx]);
    if (ret < 0)
        return ret;
    idx += (word32)ret;
    XMEMCPY(&out[idx], s, sLen);
    idx += sLen;

    *outLen = idx;

    return 0;
}

int DecodeECC_DSA_Sig_Bin(const byte* sig, word32 sigLen, byte* r, word32* rLen,
    byte* s, word32* sLen)
{
    int    ret;
    word32 idx = 0;
    int    len = 0;

    if (GetSequence(sig, &idx, &len, sigLen) < 0) {
        return ASN_ECC_KEY_E;
    }

#ifndef NO_STRICT_ECDSA_LEN
    /* enable strict length checking for signature */
    if (sigLen != idx + (word32)len) {
        return ASN_ECC_KEY_E;
    }
#else
    /* allow extra signature bytes at end */
    if ((word32)len > (sigLen - idx)) {
        return ASN_ECC_KEY_E;
    }
#endif

    ret = GetASNInt(sig, &idx, &len, sigLen);
    if (ret != 0)
        return ret;
    if (rLen) {
        if (*rLen >= (word32)len)
            *rLen = (word32)len;
        else {
            /* Buffer too small to hold r value */
            return BUFFER_E;
        }
    }
    if (r)
        XMEMCPY(r, (byte*)sig + idx, (size_t)len);
    idx += (word32)len;

    ret = GetASNInt(sig, &idx, &len, sigLen);
    if (ret != 0)
        return ret;
    if (sLen) {
        if (*sLen >= (word32)len)
            *sLen = (word32)len;
        else {
            /* Buffer too small to hold s value */
            return BUFFER_E;
        }
    }
    if (s)
        XMEMCPY(s, (byte*)sig + idx, (size_t)len);

#ifndef NO_STRICT_ECDSA_LEN
    /* sanity check that the index has been advanced all the way to the end of
     * the buffer */
    if (idx + (word32)len != sigLen) {
        ret = ASN_ECC_KEY_E;
    }
#endif

    return ret;
}

int DecodeECC_DSA_Sig_Ex(const byte* sig, word32 sigLen, mp_int* r, mp_int* s,
    int init)
{
    word32 idx = 0;
    int    len = 0;

    if (GetSequence(sig, &idx, &len, sigLen) < 0) {
        return ASN_ECC_KEY_E;
    }

#ifndef NO_STRICT_ECDSA_LEN
    /* enable strict length checking for signature */
    if (sigLen != idx + (word32)len) {
        return ASN_ECC_KEY_E;
    }
#else
    /* allow extra signature bytes at end */
    if ((word32)len > (sigLen - idx)) {
        return ASN_ECC_KEY_E;
    }
#endif

    if (GetIntPositive(r, sig, &idx, sigLen, init) < 0) {
        return ASN_ECC_KEY_E;
    }

    if (GetIntPositive(s, sig, &idx, sigLen, init) < 0) {
        mp_clear(r);
        return ASN_ECC_KEY_E;
    }

#ifndef NO_STRICT_ECDSA_LEN
    /* sanity check that the index has been advanced all the way to the end of
     * the buffer */
    if (idx != sigLen) {
        mp_clear(r);
        mp_clear(s);
        return ASN_ECC_KEY_E;
    }
#endif

    return 0;
}

#endif
#ifdef HAVE_ECC
WOLFSSL_ABI
int wc_EccPrivateKeyDecode(const byte* input, word32* inOutIdx, ecc_key* key,
                        word32 inSz)
{
    word32 oidSum;
    int    version, length;
    int    privSz, pubSz = 0;
    byte   b;
    int    ret = 0;
    int    curve_id = ECC_CURVE_DEF;
#ifdef WOLFSSL_SMALL_STACK
    byte* priv;
    byte* pub = NULL;
#else
    byte priv[ECC_MAXSIZE+1];
    byte pub[2*(ECC_MAXSIZE+1)]; /* public key has two parts plus header */
#endif
    word32 algId = 0;
    byte* pubData = NULL;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    /* if has pkcs8 header skip it */
    if (ToTraditionalInline_ex(input, inOutIdx, inSz, &algId) < 0) {
        /* ignore error, did not have pkcs8 header */
    }
    else {
        curve_id = wc_ecc_get_oid(algId, NULL, NULL);
    }

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    if (GetMyVersion(input, inOutIdx, &version, inSz) < 0)
        return ASN_PARSE_E;

    if (*inOutIdx >= inSz)
        return ASN_PARSE_E;

    b = input[*inOutIdx];
    *inOutIdx += 1;

    /* priv type */
    if (b != 4 && b != 6 && b != 7)
        return ASN_PARSE_E;

    if (GetLength(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;
    privSz = length;

    if (privSz > ECC_MAXSIZE)
        return BUFFER_E;

    WC_ALLOC_VAR_EX(priv, byte, privSz, key->heap, DYNAMIC_TYPE_TMP_BUFFER,
        return MEMORY_E);

    /* priv key */
    XMEMCPY(priv, &input[*inOutIdx], (size_t)privSz);
    *inOutIdx += (word32)length;

    if ((*inOutIdx + 1) < inSz) {
        /* prefix 0, may have */
        b = input[*inOutIdx];
        if (b == ECC_PREFIX_0) {
            *inOutIdx += 1;

            if (GetLength(input, inOutIdx, &length, inSz) <= 0)
                ret = ASN_PARSE_E;
            else {
                ret = GetObjectId(input, inOutIdx, &oidSum, oidIgnoreType,
                                  inSz);
                if (ret == 0) {
                    if ((ret = CheckCurve(oidSum)) < 0)
                        ret = ECC_CURVE_OID_E;
                    else {
                        curve_id = ret;
                        ret = 0;
                    }
                }
            }
        }
    }

    if (ret == 0 && (*inOutIdx + 1) < inSz) {
        /* prefix 1 */
        b = input[*inOutIdx];
        *inOutIdx += 1;

        if (b != ECC_PREFIX_1) {
            ret = ASN_ECC_KEY_E;
        }
        else if (GetLength(input, inOutIdx, &length, inSz) <= 0) {
            ret = ASN_PARSE_E;
        }
        else {
            /* key header */
            ret = CheckBitString(input, inOutIdx, &length, inSz, 0, NULL);
            if (ret == 0) {
                /* pub key */
                pubSz = length;
                if (pubSz > 2*(ECC_MAXSIZE+1))
                    ret = BUFFER_E;
                else {
                    WC_ALLOC_VAR_EX(pub, byte, pubSz, key->heap,
                        DYNAMIC_TYPE_TMP_BUFFER, ret=MEMORY_E);
                    if (WC_VAR_OK(pub))
                    {
                        XMEMCPY(pub, &input[*inOutIdx], (size_t)pubSz);
                        *inOutIdx += (word32)length;
                        pubData = pub;
                    }
                }
            }
        }
    }

    if (ret == 0) {
        ret = wc_ecc_import_private_key_ex(priv, (word32)privSz, pubData,
            (word32)pubSz, key, curve_id);
    }

    WC_FREE_VAR_EX(priv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    WC_FREE_VAR_EX(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#ifdef WOLFSSL_CUSTOM_CURVES
/* returns 0 on success */
static int ASNToHexString(const byte* input, word32* inOutIdx, char** out,
                          word32 inSz, void* heap, int heapType)
{
    int len;
    int i;
    char* str;
    word32 localIdx;
    byte   tag;

    if (*inOutIdx >= inSz) {
        return BUFFER_E;
    }

    localIdx = *inOutIdx;
    if (GetASNTag(input, &localIdx, &tag, inSz) == 0 && tag == ASN_INTEGER) {
        if (GetASNInt(input, inOutIdx, &len, inSz) < 0)
            return ASN_PARSE_E;
    }
    else {
        if (GetOctetString(input, inOutIdx, &len, inSz) < 0)
            return ASN_PARSE_E;
    }

    str = (char*)XMALLOC((size_t)len * 2 + 1, heap, heapType);
    if (str == NULL) {
        return MEMORY_E;
    }

    for (i=0; i<len; i++)
        ByteToHexStr(input[*inOutIdx + (word32)i], str + i*2);
    str[len*2] = '\0';

    *inOutIdx += (word32)len;
    *out = str;

    (void)heap;
    (void)heapType;

    return 0;
}

static int EccKeyParamCopy(char** dst, char* src, void* heap)
{
    int ret = 0;
#ifdef WOLFSSL_ECC_CURVE_STATIC
    word32 length;
#endif

    if (dst == NULL || src == NULL)
        return BAD_FUNC_ARG;

#ifndef WOLFSSL_ECC_CURVE_STATIC
    *dst = src;
#else
    length = (int)XSTRLEN(src) + 1;
    if (length > MAX_ECC_STRING) {
        WOLFSSL_MSG("ECC Param too large for buffer");
        ret = BUFFER_E;
    }
    else {
        XSTRNCPY(*dst, src, MAX_ECC_STRING);
    }
    XFREE(src, heap, DYNAMIC_TYPE_ECC_BUFFER);
#endif
    (void)heap;

    return ret;
}

#endif
WOLFSSL_ABI
int wc_EccPublicKeyDecode(const byte* input, word32* inOutIdx,
                          ecc_key* key, word32 inSz)
{
    int    ret;
    int    version, length;
    int    curve_id = ECC_CURVE_DEF;
    word32 oidSum, localIdx;
    byte   tag, isPrivFormat = 0;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0)
        return BAD_FUNC_ARG;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    /* Check if ECC private key is being used and skip private portion */
    if (GetMyVersion(input, inOutIdx, &version, inSz) >= 0) {
        isPrivFormat = 1;

        /* Type private key */
        if (*inOutIdx >= inSz)
            return ASN_PARSE_E;
        tag = input[*inOutIdx];
        *inOutIdx += 1;
        if (tag != 4 && tag != 6 && tag != 7)
            return ASN_PARSE_E;

        /* Skip Private Key */
        if (GetLength(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;
        if (length > ECC_MAXSIZE)
            return BUFFER_E;
        *inOutIdx += (word32)length;

        /* Private Curve Header */
        if (*inOutIdx >= inSz)
            return ASN_PARSE_E;
        tag = input[*inOutIdx];
        *inOutIdx += 1;
        if (tag != ECC_PREFIX_0)
            return ASN_ECC_KEY_E;
        if (GetLength(input, inOutIdx, &length, inSz) <= 0)
            return ASN_PARSE_E;
    }
    /* Standard ECC public key */
    else {
        if (GetSequence(input, inOutIdx, &length, inSz) < 0)
            return ASN_PARSE_E;

        ret = SkipObjectId(input, inOutIdx, inSz);
        if (ret != 0)
            return ret;
    }

    if (*inOutIdx >= inSz) {
        return BUFFER_E;
    }

    localIdx = *inOutIdx;
    if (GetASNTag(input, &localIdx, &tag, inSz) == 0 &&
            tag == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
#ifdef WOLFSSL_CUSTOM_CURVES
        ecc_set_type* curve;
        int len;
        char* point = NULL;

        ret = 0;

        curve = (ecc_set_type*)XMALLOC(sizeof(*curve), key->heap,
                                                       DYNAMIC_TYPE_ECC_BUFFER);
        if (curve == NULL)
            ret = MEMORY_E;

        if (ret == 0) {
            static const char customName[] = "Custom";
            XMEMSET(curve, 0, sizeof(*curve));
        #ifndef WOLFSSL_ECC_CURVE_STATIC
            curve->name = customName;
        #else
            XMEMCPY((void*)curve->name, customName, sizeof(customName));
        #endif
            curve->id = ECC_CURVE_CUSTOM;

            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
        }

        if (ret == 0) {
            GetInteger7Bit(input, inOutIdx, inSz);
            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
        }
        if (ret == 0) {
            char* p = NULL;
            SkipObjectId(input, inOutIdx, inSz);
            ret = ASNToHexString(input, inOutIdx, &p, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0) {
#ifndef WOLFSSL_ECC_CURVE_STATIC
                ret = EccKeyParamCopy((char**)&curve->prime, p, key->heap);
#else
                const char *_tmp_ptr = &curve->prime[0];
                ret = EccKeyParamCopy((char**)&_tmp_ptr, p, key->heap);
#endif
            }
        }
        if (ret == 0) {
            curve->size = (int)XSTRLEN(curve->prime) / 2;

            if (GetSequence(input, inOutIdx, &length, inSz) < 0)
                ret = ASN_PARSE_E;
        }
        if (ret == 0) {
            char* af = NULL;
            ret = ASNToHexString(input, inOutIdx, &af, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0) {
#ifndef WOLFSSL_ECC_CURVE_STATIC
                ret = EccKeyParamCopy((char**)&curve->Af, af, key->heap);
#else
                const char *_tmp_ptr = &curve->Af[0];
                ret = EccKeyParamCopy((char**)&_tmp_ptr, af, key->heap);
#endif
            }
        }
        if (ret == 0) {
            char* bf = NULL;
            ret = ASNToHexString(input, inOutIdx, &bf, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0) {
#ifndef WOLFSSL_ECC_CURVE_STATIC
                ret = EccKeyParamCopy((char**)&curve->Bf, bf, key->heap);
#else
                const char *_tmp_ptr = &curve->Bf[0];
                ret = EccKeyParamCopy((char**)&_tmp_ptr, bf, key->heap);
#endif
            }
        }
        if (ret == 0) {
            localIdx = *inOutIdx;
            if (*inOutIdx < inSz && GetASNTag(input, &localIdx, &tag, inSz)
                    == 0 && tag == ASN_BIT_STRING) {
                len = 0;
                ret = GetASNHeader(input, ASN_BIT_STRING, inOutIdx, &len, inSz);
                if (ret > 0)
                    ret = 0; /* reset on success */
                *inOutIdx += (word32)len;
            }
        }
        if (ret == 0) {
            ret = ASNToHexString(input, inOutIdx, (char**)&point, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);

            /* sanity check that point buffer is not smaller than the expected
             * size to hold ( 0 4 || Gx || Gy )
             * where Gx and Gy are each the size of curve->size * 2 */
            if (ret == 0 && (int)XSTRLEN(point) < (curve->size * 4) + 2) {
                XFREE(point, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
                ret = BUFFER_E;
            }
        }
        if (ret == 0) {
        #ifndef WOLFSSL_ECC_CURVE_STATIC
            curve->Gx = (const char*)XMALLOC((size_t)curve->size * 2 + 2,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            curve->Gy = (const char*)XMALLOC((size_t)curve->size * 2 + 2,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (curve->Gx == NULL || curve->Gy == NULL) {
                XFREE(point, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
                ret = MEMORY_E;
            }
        #else
            if (curve->size * 2 + 2 > MAX_ECC_STRING) {
                WOLFSSL_MSG("curve size is too large to fit in buffer");
                ret = BUFFER_E;
            }
        #endif
        }
        if (ret == 0) {
            char* o = NULL;

            XMEMCPY((char*)curve->Gx, point + 2, (size_t)curve->size * 2);
            XMEMCPY((char*)curve->Gy, point + curve->size * 2 + 2,
                                                 (size_t)curve->size * 2);
            ((char*)curve->Gx)[curve->size * 2] = '\0';
            ((char*)curve->Gy)[curve->size * 2] = '\0';
            XFREE(point, key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            ret = ASNToHexString(input, inOutIdx, &o, inSz,
                                            key->heap, DYNAMIC_TYPE_ECC_BUFFER);
            if (ret == 0) {
#ifndef WOLFSSL_ECC_CURVE_STATIC
                ret = EccKeyParamCopy((char**)&curve->order, o, key->heap);
#else
                const char *_tmp_ptr = &curve->order[0];
                ret = EccKeyParamCopy((char**)&_tmp_ptr, o, key->heap);
#endif
            }
        }
        if (ret == 0) {
            curve->cofactor = GetInteger7Bit(input, inOutIdx, inSz);

        #ifndef WOLFSSL_ECC_CURVE_STATIC
            curve->oid = NULL;
        #else
            XMEMSET((void*)curve->oid, 0, sizeof(curve->oid));
        #endif
            curve->oidSz = 0;
            curve->oidSum = 0;

            if (wc_ecc_set_custom_curve(key, curve) < 0) {
                ret = ASN_PARSE_E;
            }

            key->deallocSet = 1;

            curve = NULL;
        }
        if (curve != NULL)
            wc_ecc_free_curve(curve, key->heap);

        if (ret < 0)
            return ret;
#else
        return ASN_PARSE_E;
#endif /* WOLFSSL_CUSTOM_CURVES */
    }
    else {
        /* ecc params information */
        ret = GetObjectId(input, inOutIdx, &oidSum, oidIgnoreType, inSz);
        if (ret != 0)
            return ret;

        /* get curve id */
        if ((ret = CheckCurve(oidSum)) < 0)
            return ECC_CURVE_OID_E;
        else {
            curve_id = ret;
        }
    }

    if (isPrivFormat) {
        /* Public Curve Header - skip */
        if (*inOutIdx >= inSz)
            return ASN_PARSE_E;
        tag = input[*inOutIdx];
        *inOutIdx += 1;
        if (tag != ECC_PREFIX_1)
            return ASN_ECC_KEY_E;
        if (GetLength(input, inOutIdx, &length, inSz) <= 0)
            return ASN_PARSE_E;
    }

    /* key header */
    ret = CheckBitString(input, inOutIdx, &length, inSz, 1, NULL);
    if (ret != 0)
        return ret;

    /* This is the raw point data compressed or uncompressed. */
    if (wc_ecc_import_x963_ex(input + *inOutIdx, (word32)length, key,
                                                            curve_id) != 0) {
        return ASN_ECC_KEY_E;
    }

    *inOutIdx += (word32)length;

    return 0;
}

#ifdef HAVE_ECC_KEY_EXPORT
int wc_BuildEccKeyDer(ecc_key* key, byte* output, word32 *inLen,
                             int pubIn, int curveIn)
{
    byte   curve[MAX_ALGO_SZ+2];
    byte   ver[MAX_VERSION_SZ];
    byte   seq[MAX_SEQ_SZ];
    int    ret, curveSz, verSz;
    word32 totalSz;
    int    privHdrSz  = ASN_ECC_HEADER_SZ;
    int    pubHdrSz   = ASN_ECC_CONTEXT_SZ + ASN_ECC_HEADER_SZ;
#ifdef WOLFSSL_NO_MALLOC
    byte   prv[MAX_ECC_BYTES + ASN_ECC_HEADER_SZ + MAX_SEQ_SZ];
    byte   pub[(MAX_ECC_BYTES * 2) + 1 + ASN_ECC_CONTEXT_SZ +
                              ASN_ECC_HEADER_SZ + MAX_SEQ_SZ];
#else
    byte   *prv = NULL, *pub = NULL;
#endif

    word32 idx = 0, prvidx = 0, pubidx = 0, curveidx = 0;
    word32 seqSz, privSz, pubSz = ECC_BUFSIZE;

    if (key == NULL || (output == NULL && inLen == NULL))
        return BAD_FUNC_ARG;

    if (curveIn) {
        /* curve */
        curve[curveidx++] = ECC_PREFIX_0;
        curveidx++ /* to put the size after computation */;
        curveSz = SetCurve(key, curve+curveidx, MAX_ALGO_SZ);
        if (curveSz < 0)
            return curveSz;
        /* set computed size */
        curve[1] = (byte)curveSz;
        curveidx += (word32)curveSz;
    }

    /* private */
    privSz = (word32)key->dp->size;

#ifdef WOLFSSL_QNX_CAAM
    /* check if is a black key, and add MAC size if needed */
    if (key->blackKey > 0 && key->blackKey != CAAM_BLACK_KEY_ECB) {
        privSz = privSz + WC_CAAM_MAC_SZ;
    }
#endif

#ifndef WOLFSSL_NO_MALLOC
    prv = (byte*)XMALLOC(privSz + (word32)privHdrSz + MAX_SEQ_SZ,
                         key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (prv == NULL) {
        return MEMORY_E;
    }
#else
    if (sizeof(prv) < privSz + privHdrSz + MAX_SEQ_SZ) {
        return BUFFER_E;
    }
#endif
    if (privSz < ASN_LONG_LENGTH) {
        prvidx += SetOctetString8Bit(privSz, &prv[prvidx]);
    }
    else {
        prvidx += SetOctetString(privSz, &prv[prvidx]);
    }
    ret = wc_ecc_export_private_only(key, prv + prvidx, &privSz);
    if (ret < 0) {
    #ifndef WOLFSSL_NO_MALLOC
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return ret;
    }
    prvidx += privSz;

    /* pubIn */
    if (pubIn) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(key, NULL, &pubSz);
        PRIVATE_KEY_LOCK();
        if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
        #ifndef WOLFSSL_NO_MALLOC
            XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return ret;
        }

    #ifndef WOLFSSL_NO_MALLOC
        pub = (byte*)XMALLOC(pubSz + (word32)pubHdrSz + MAX_SEQ_SZ,
                             key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (pub == NULL) {
            XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
    #else
        if (sizeof(pub) < pubSz + pubHdrSz + MAX_SEQ_SZ) {
            return BUFFER_E;
        }
    #endif

        pub[pubidx++] = ECC_PREFIX_1;
        if (pubSz > 128) /* leading zero + extra size byte */
            pubidx += SetLength(pubSz + ASN_ECC_CONTEXT_SZ + 2, pub+pubidx);
        else /* leading zero */
            pubidx += SetLength(pubSz + ASN_ECC_CONTEXT_SZ + 1, pub+pubidx);

        /* SetBitString adds leading zero */
        pubidx += SetBitString(pubSz, 0, pub + pubidx);
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_export_x963(key, pub + pubidx, &pubSz);
        PRIVATE_KEY_LOCK();
        if (ret != 0) {
        #ifndef WOLFSSL_NO_MALLOC
            XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
            return ret;
        }
        pubidx += pubSz;
    }

    /* make headers */
    verSz = SetMyVersion(1, ver, FALSE);
    seqSz = SetSequence((word32)verSz + prvidx + pubidx + curveidx, seq);

    totalSz = prvidx + pubidx + curveidx + (word32)verSz + seqSz;
    if (output == NULL) {
        *inLen = totalSz;
    #ifndef WOLFSSL_NO_MALLOC
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (pubIn) {
            XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
    #endif
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }
    if (inLen != NULL && totalSz > *inLen) {
        #ifndef WOLFSSL_NO_MALLOC
        XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (pubIn) {
            XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        #endif
        return BAD_FUNC_ARG;
    }

    /* write out */
    /* seq */
    XMEMCPY(output + idx, seq, seqSz);
    idx = seqSz;

    /* ver */
    XMEMCPY(output + idx, ver, (size_t)verSz);
    idx += (word32)verSz;

    /* private */
    XMEMCPY(output + idx, prv, prvidx);
    idx += prvidx;
#ifndef WOLFSSL_NO_MALLOC
    XFREE(prv, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    /* curve */
    XMEMCPY(output + idx, curve, curveidx);
    idx += curveidx;

    /* pubIn */
    if (pubIn) {
        XMEMCPY(output + idx, pub, pubidx);
        /* idx += pubidx;  not used after write, if more data remove comment */
    #ifndef WOLFSSL_NO_MALLOC
        XFREE(pub, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }

    return (int)totalSz;
}

#endif
#endif
#if (defined(HAVE_OCSP) || defined(HAVE_CRL)) && !defined(WOLFCRYPT_ONLY)

/* Get raw Date only, no processing, 0 on success */
static int GetBasicDate(const byte* source, word32* idx, byte* date,
                        byte* format, int maxIdx)
{
    int    ret, length;
    const byte *datePtr = NULL;

    WOLFSSL_ENTER("GetBasicDate");

    ret = GetDateInfo(source, idx, &datePtr, format, &length, maxIdx);
    if (ret < 0)
        return ret;

    XMEMCPY(date, datePtr, length);

    return 0;
}

#endif /* HAVE_OCSP || HAVE_CRL */

#if defined(HAVE_OCSP) && !defined(WOLFCRYPT_ONLY)
static int GetEnumerated(const byte* input, word32* inOutIdx, int *value,
        int sz)
{
    word32 idx = *inOutIdx;
    word32 len;
    byte   tag;

    WOLFSSL_ENTER("GetEnumerated");

    *value = 0;

    if (GetASNTag(input, &idx, &tag, sz) < 0)
        return ASN_PARSE_E;

    if (tag != ASN_ENUMERATED)
        return ASN_PARSE_E;

    if ((int)idx >= sz)
        return BUFFER_E;

    len = input[idx++];
    if (len > 4 || (int)(len + idx) > sz)
        return ASN_PARSE_E;

    while (len--) {
        *value  = *value << 8 | input[idx++];
    }

    *inOutIdx = idx;

    return *value;
}

#ifdef HAVE_OCSP_RESPONDER
WC_MAYBE_UNUSED static int EncodeCertID(OcspEntry* entry, byte* out,
        word32* outSz)
{
    (void)entry;
    (void)out;
    (void)outSz;
    /* Encoding ocsp CertID not supported in legacy ASN parsing */
    return NOT_COMPILED_IN;
}

#endif
static int OcspDecodeCertIDInt(const byte* input, word32* inOutIdx, word32 inSz,
                 OcspEntry* entry)
{
    int length;
    word32 oid;
    int ret;
    int expectedDigestSz;

    /* Hash algorithm */
    ret = GetAlgoId(input, inOutIdx, &oid, oidHashType, inSz);
    if (ret < 0)
        return ret;
    entry->hashAlgoOID = oid;

    /* Validate hash algorithm and get expected digest size */
    expectedDigestSz = wc_HashGetDigestSize(wc_OidGetHash((int)oid));
    if (expectedDigestSz <= 0)
        return ASN_SIG_HASH_E;

    /* Save reference to the hash of CN */
    ret = GetOctetString(input, inOutIdx, &length, inSz);
    if (ret < 0)
        return ret;
    if (length != expectedDigestSz || length > (int)sizeof(entry->issuerHash))
        return ASN_PARSE_E;
    XMEMCPY(entry->issuerHash, input + *inOutIdx, length);
    *inOutIdx += length;
    /* Save reference to the hash of the issuer public key */
    ret = GetOctetString(input, inOutIdx, &length, inSz);
    if (ret < 0)
        return ret;
    if (length != expectedDigestSz || length > (int)sizeof(entry->issuerKeyHash))
        return ASN_PARSE_E;
    XMEMCPY(entry->issuerKeyHash, input + *inOutIdx, length);
    *inOutIdx += length;

    /* Get serial number */
    if (wc_GetSerialNumber(input, inOutIdx, entry->status->serial,
                        &entry->status->serialSz, inSz) < 0)
        return ASN_PARSE_E;
    return 0;
}

#ifdef HAVE_OCSP_RESPONDER
WC_MAYBE_UNUSED static int EncodeSingleResponse(OcspEntry* single, byte* out,
        word32* outSz, void* heap)
{
    (void)single;
    (void)out;
    (void)outSz;
    (void)heap;
    /* Encoding ocsp responses not supported in legacy ASN parsing */
    return NOT_COMPILED_IN;
}

#endif
static int DecodeSingleResponse(byte* source, word32* ioIndex, word32 size,
                                int wrapperSz, OcspEntry* single)
{
    word32 idx = *ioIndex, prevIndex, localIdx, certIdIdx;
    int length;
    int ret;
    byte tag;

    WOLFSSL_ENTER("DecodeSingleResponse");

    prevIndex = idx;

    /* Wrapper around the Single Response */
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    /* Wrapper around the CertID */
    certIdIdx = idx;
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    single->rawCertId = source + certIdIdx;
    ret = OcspDecodeCertIDInt(source, &idx, size, single);
    if (ret < 0)
        return ASN_PARSE_E;
    single->rawCertIdSize = idx - certIdIdx;

    if (idx >= size)
        return BUFFER_E;

    /* CertStatus */
    switch (source[idx++])
    {
        case (ASN_CONTEXT_SPECIFIC | CERT_GOOD):
            single->status->status = CERT_GOOD;
            idx++;
            break;
        case (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | CERT_REVOKED):
            single->status->status = CERT_REVOKED;
            if (GetLength(source, &idx, &length, size) < 0)
                return ASN_PARSE_E;
            idx += length;
            break;
        case (ASN_CONTEXT_SPECIFIC | CERT_UNKNOWN):
            single->status->status = CERT_UNKNOWN;
            idx++;
            break;
        default:
            return ASN_PARSE_E;
    }

    if (idx >= size)
        return BUFFER_E;

#ifdef WOLFSSL_OCSP_PARSE_STATUS
    single->status->thisDateAsn = source + idx;
    localIdx = 0;
    if (GetDateInfo(single->status->thisDateAsn, &localIdx, NULL,
                    (byte*)&single->status->thisDateParsed.type,
                    &single->status->thisDateParsed.length, size - idx) < 0)
        return ASN_PARSE_E;

    if (idx + localIdx >= size)
        return BUFFER_E;

    XMEMCPY(single->status->thisDateParsed.data,
            single->status->thisDateAsn + localIdx - single->status->thisDateParsed.length,
            single->status->thisDateParsed.length);
#endif
    if (GetBasicDate(source, &idx, single->status->thisDate,
                     &single->status->thisDateFormat, size) < 0)
        return ASN_PARSE_E;

#ifndef NO_ASN_TIME_CHECK
#ifndef WOLFSSL_NO_OCSP_DATE_CHECK
    if ((! AsnSkipDateCheck) && !XVALIDATE_DATE(single->status->thisDate,
        single->status->thisDateFormat, ASN_BEFORE, MAX_DATE_SIZE))
        return ASN_BEFORE_DATE_E;
#endif
#endif

    /* The following items are optional. Only check for them if there is more
     * unprocessed data in the singleResponse wrapper. */
    localIdx = idx;
    if (((int)(idx - prevIndex) < wrapperSz) &&
        GetASNTag(source, &localIdx, &tag, size) == 0 &&
        tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
    {
        idx++;
        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;
#ifdef WOLFSSL_OCSP_PARSE_STATUS
        single->status->nextDateAsn = source + idx;
        localIdx = 0;
        if (GetDateInfo(single->status->nextDateAsn, &localIdx, NULL,
                        (byte*)&single->status->nextDateParsed.type,
                        &single->status->nextDateParsed.length, size - idx) < 0)
            return ASN_PARSE_E;

        if (idx + localIdx >= size)
            return BUFFER_E;

        XMEMCPY(single->status->nextDateParsed.data,
                single->status->nextDateAsn + localIdx - single->status->nextDateParsed.length,
                single->status->nextDateParsed.length);
#endif
        if (GetBasicDate(source, &idx, single->status->nextDate,
                         &single->status->nextDateFormat, size) < 0)
            return ASN_PARSE_E;

#ifndef NO_ASN_TIME_CHECK
#ifndef WOLFSSL_NO_OCSP_DATE_CHECK
        if ((! AsnSkipDateCheck) &&
            !XVALIDATE_DATE(single->status->nextDate,
                            single->status->nextDateFormat, ASN_AFTER, MAX_DATE_SIZE))
            return ASN_AFTER_DATE_E;
#endif
#endif
    }

    /* Skip the optional extensions in singleResponse. */
    localIdx = idx;
    if (((int)(idx - prevIndex) < wrapperSz) &&
        GetASNTag(source, &localIdx, &tag, size) == 0 &&
        tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1))
    {
        idx++;
        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;
        idx += length;
    }

    *ioIndex = idx;

    return 0;
}

static int DecodeOcspRespExtensions(byte* source, word32* ioIndex,
                                    OcspResponse* resp, word32 sz)
{
    word32 idx = *ioIndex;
    int length;
    int ext_bound; /* boundary index for the sequence of extensions */
    word32 oid;
    int ret;
    byte tag;

    WOLFSSL_ENTER("DecodeOcspRespExtensions");

    if ((idx + 1) > sz)
        return BUFFER_E;

    if (GetASNTag(source, &idx, &tag, sz) < 0)
        return ASN_PARSE_E;

    if (tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1))
        return ASN_PARSE_E;

    if (GetLength(source, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetSequence(source, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    ext_bound = idx + length;

    while (idx < (word32)ext_bound) {
        word32 localIdx;

        if (GetSequence(source, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        oid = 0;
        if (GetObjectId(source, &idx, &oid, oidOcspType, sz) < 0) {
            WOLFSSL_MSG("\tfail: OBJECT ID");
            return ASN_PARSE_E;
        }

        /* check for critical flag */
        if ((idx + 1) > (word32)sz) {
            WOLFSSL_MSG("\tfail: malformed buffer");
            return BUFFER_E;
        }

        localIdx = idx;
        if (GetASNTag(source, &localIdx, &tag, sz) == 0 && tag == ASN_BOOLEAN) {
            WOLFSSL_MSG("\tfound optional critical flag, moving past");
            ret = GetBoolean(source, &idx, sz);
            if (ret < 0)
                return ret;
        }

        ret = GetOctetString(source, &idx, &length, sz);
        if (ret < 0)
            return ret;

        if (oid == OCSP_NONCE_OID) {
            /* get data inside extra OCTET_STRING */
            ret = GetOctetString(source, &idx, &length, sz);
            if (ret < 0)
                return ret;

            resp->nonce = source + idx;
            resp->nonceSz = length;
        }

        idx += length;
    }

    *ioIndex = idx;
    return 0;
}

WC_MAYBE_UNUSED static int EncodeOcspRespExtensions(OcspResponse* resp,
        byte* out, word32* outSz)
{
    (void)resp;
    (void)out;
    (void)outSz;
    /* Encoding ocsp responses not supported in legacy ASN parsing */
    return NOT_COMPILED_IN;
}

#ifdef HAVE_OCSP_RESPONDER
WC_MAYBE_UNUSED static int EncodeResponseData(OcspResponse* resp, byte* out,
        word32* outSz)
{
    (void)resp;
    (void)out;
    (void)outSz;
    /* Encoding ocsp responses not supported in legacy ASN parsing */
    return NOT_COMPILED_IN;
}

#endif
static int DecodeResponseData(byte* source, word32* ioIndex,
                              OcspResponse* resp, word32 size)
{
    word32 idx = *ioIndex, prev_idx, localIdx;
    int length;
    int version;
    int ret;
    byte tag;
    int wrapperSz;
    OcspEntry* single;

    WOLFSSL_ENTER("DecodeResponseData");

    resp->response = source + idx;
    prev_idx = idx;
    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;
    resp->responseSz = length + idx - prev_idx;

    /* Get version. It is an EXPLICIT[0] DEFAULT(0) value. If this
     * item isn't an EXPLICIT[0], then set version to zero and move
     * onto the next item.
     */
    localIdx = idx;
    if (GetASNTag(source, &localIdx, &tag, size) == 0 &&
            tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
    {
        idx += 2; /* Eat the value and length */
        if (GetMyVersion(source, &idx, &version, size) < 0)
            return ASN_PARSE_E;
    } else
        version = 0;

    localIdx = idx;
    if (GetASNTag(source, &localIdx, &tag, size) != 0)
        return ASN_PARSE_E;

    resp->responderIdType = OCSP_RESPONDER_ID_INVALID;
    /* parse byName */
    if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
    {
        idx++; /* advance past ASN tag */
        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;
        /* compute the hash of the name */
        resp->responderIdType = OCSP_RESPONDER_ID_NAME;
        ret = CalcHashId_ex(source + idx, length,
                resp->responderId.nameHash, OCSP_RESPONDER_ID_HASH_TYPE);
        if (ret != 0)
            return ret;
        idx += length;
    }
    else if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2))
    {
        idx++; /* advance past ASN tag */
        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;

        if (GetOctetString(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;

        if (length != OCSP_RESPONDER_ID_KEY_SZ)
            return ASN_PARSE_E;
        resp->responderIdType = OCSP_RESPONDER_ID_KEY;
        XMEMCPY(resp->responderId.keyHash, source + idx, length);
        idx += length;
    }
    if (resp->responderIdType == OCSP_RESPONDER_ID_INVALID)
        return ASN_PARSE_E;

    /* save pointer to the producedAt time */
    if (GetBasicDate(source, &idx, resp->producedDate,
                                        &resp->producedDateFormat, size) < 0)
        return ASN_PARSE_E;

    /* Outer wrapper of the SEQUENCE OF Single Responses. */
    if (GetSequence(source, &idx, &wrapperSz, size) < 0)
        return ASN_PARSE_E;

    localIdx = idx;
    single = resp->single;
    while (idx - localIdx < (word32)wrapperSz) {
        ret = DecodeSingleResponse(source, &idx, size, wrapperSz, single);
        if (ret < 0)
            return ret; /* ASN_PARSE_E, ASN_BEFORE_DATE_E, ASN_AFTER_DATE_E */
        if (idx - localIdx < (word32)wrapperSz) {
            single->next = (OcspEntry*)XMALLOC(sizeof(OcspEntry), resp->heap,
                DYNAMIC_TYPE_OCSP_ENTRY);
            if (single->next == NULL) {
                return MEMORY_E;
            }
            XMEMSET(single->next, 0, sizeof(OcspEntry));

            single->next->status = (CertStatus*)XMALLOC(sizeof(CertStatus),
                resp->heap, DYNAMIC_TYPE_OCSP_STATUS);
            if (single->next->status == NULL) {
                XFREE(single->next, resp->heap, DYNAMIC_TYPE_OCSP_ENTRY);
                single->next = NULL;
                return MEMORY_E;
            }
            XMEMSET(single->next->status, 0, sizeof(CertStatus));

            single->next->isDynamic = 1;
            single->next->ownStatus = 1;

            single = single->next;
        }
    }

    /*
     * Check the length of the ResponseData against the current index to
     * see if there are extensions, they are optional.
     */
    if (idx - prev_idx < resp->responseSz)
        if (DecodeOcspRespExtensions(source, &idx, resp, size) < 0)
            return ASN_PARSE_E;

    *ioIndex = idx;
    return 0;
}

#ifndef WOLFSSL_NO_OCSP_OPTIONAL_CERTS

static int DecodeCerts(byte* source,
                            word32* ioIndex, OcspResponse* resp, word32 size)
{
    word32 idx = *ioIndex;
    byte tag;

    WOLFSSL_ENTER("DecodeCerts");

    if (GetASNTag(source, &idx, &tag, size) < 0)
        return ASN_PARSE_E;

    if (tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC))
    {
        int length;

        if (GetLength(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;

        if (GetSequence(source, &idx, &length, size) < 0)
            return ASN_PARSE_E;

        resp->cert = source + idx;
        resp->certSz = length;

        idx += length;
    }
    *ioIndex = idx;
    return 0;
}

#endif /* WOLFSSL_NO_OCSP_OPTIONAL_CERTS */

#ifdef HAVE_OCSP_RESPONDER
WC_MAYBE_UNUSED static int EncodeBasicOcspResponse(OcspResponse* resp,
        byte* out, word32* outSz, RsaKey* rsaKey, ecc_key* eccKey, WC_RNG* rng)
{
    (void)resp;
    (void)out;
    (void)outSz;
    (void)rsaKey;
    (void)eccKey;
    (void)rng;
    /* Encoding ocsp responses not supported in legacy ASN parsing */
    return NOT_COMPILED_IN;
}

#endif
static int DecodeBasicOcspResponse(byte* source, word32* ioIndex,
            OcspResponse* resp, word32 size, void* cm, void* heap, int noVerify,
            int noVerifySignature)
{
    int    length;
    word32 idx = *ioIndex;
    #ifndef WOLFSSL_NO_OCSP_OPTIONAL_CERTS
    word32 end_index;
    #endif
    int    ret;
    int    sigLength;
    int    sigValid = 0;
    WOLFSSL_ENTER("DecodeBasicOcspResponse");
    (void)heap;

    if (GetSequence(source, &idx, &length, size) < 0)
        return ASN_PARSE_E;

    if (idx + length > size)
        return ASN_INPUT_E;
    #ifndef WOLFSSL_NO_OCSP_OPTIONAL_CERTS
    end_index = idx + length;
    #endif

    if ((ret = DecodeResponseData(source, &idx, resp, size)) < 0)
        return ret; /* ASN_PARSE_E, ASN_BEFORE_DATE_E, ASN_AFTER_DATE_E */

    /* Get the signature algorithm */
    if (GetAlgoId(source, &idx, &resp->sigOID, oidSigType, size) < 0) {
        return ASN_PARSE_E;
    }
#ifdef WC_RSA_PSS
    else if (resp->sigOID == CTC_RSASSAPSS) {
        word32 sz;
        int len;
        byte* params;

        sz = idx;
        params = source + idx;
        if (GetSequence(source, &idx, &len, size) < 0)
            return ASN_PARSE_E;
        if (ret == 0) {
            idx += len;
            resp->sigParams = params;
            resp->sigParamsSz = idx - sz;
        }
    }
#endif

    ret = CheckBitString(source, &idx, &sigLength, size, 1, NULL);
    if (ret != 0)
        return ret;

    resp->sigSz = sigLength;
    resp->sig = source + idx;
    idx += sigLength;

    /*
     * Check the length of the BasicOcspResponse against the current index to
     * see if there are certificates, they are optional.
     */
#ifndef WOLFSSL_NO_OCSP_OPTIONAL_CERTS
    if (idx < end_index)
    {
        if (DecodeCerts(source, &idx, resp, size) < 0)
            return ASN_PARSE_E;

        ret = OcspCheckCert(resp, noVerify, noVerifySignature,
            (WOLFSSL_CERT_MANAGER*)cm, heap);
        if (ret == 0) {
            sigValid = 1;
        }
        else {
            WOLFSSL_MSG("OCSP Internal cert can't verify the response\n");
            /* try to verify the OCSP response with CA certs */
            ret = 0;
        }
    }
#endif /* WOLFSSL_NO_OCSP_OPTIONAL_CERTS */
    if (!noVerifySignature && !sigValid) {
        Signer* ca;
        SignatureCtx sigCtx;
        ca = OcspFindSigner(resp, (WOLFSSL_CERT_MANAGER*)cm);
        if (ca == NULL)
            return ASN_NO_SIGNER_E;

#ifndef WOLFSSL_NO_OCSP_ISSUER_CHECK
        if (OcspRespCheck(resp, ca, cm) != 0)
           return BAD_OCSP_RESPONDER;
#endif
        InitSignatureCtx(&sigCtx, heap, INVALID_DEVID);

        /* ConfirmSignature is blocking here */
        sigValid = ConfirmSignature(&sigCtx, resp->response,
            resp->responseSz, ca->publicKey, ca->pubKeySize, ca->keyOID,
            resp->sig, resp->sigSz, resp->sigOID, resp->sigParams,
            resp->sigParamsSz, NULL);
        if (sigValid != 0) {
            WOLFSSL_MSG("\tOCSP Confirm signature failed");
            return ASN_OCSP_CONFIRM_E;
        }
        (void)noVerify;
    }

    *ioIndex = idx;
    return 0;
}

#ifdef HAVE_OCSP_RESPONDER
int OcspResponseEncode(OcspResponse* resp, byte* out, word32* outSz,
        RsaKey* rsaKey, ecc_key* eccKey, WC_RNG* rng)
{
    (void)resp;
    (void)out;
    (void)outSz;
    (void)rsaKey;
    (void)eccKey;
    (void)rng;
    /* Encoding ocsp responses not supported in legacy ASN parsing */
    return NOT_COMPILED_IN;
}

#endif
int OcspResponseDecode(OcspResponse* resp, void* cm, void* heap,
    int noVerifyCert, int noVerifySignature)
{
    int ret;
    int length = 0;
    word32 idx = 0;
    byte* source = resp->source;
    word32 size = resp->maxIdx;
    word32 oid;
    byte   tag;

    WOLFSSL_ENTER("OcspResponseDecode");

    /* peel the outer SEQUENCE wrapper */
    if (GetSequence(source, &idx, &length, size) < 0) {
        WOLFSSL_LEAVE("OcspResponseDecode", ASN_PARSE_E);
        return ASN_PARSE_E;
    }

    /* First get the responseStatus, an ENUMERATED */
    if (GetEnumerated(source, &idx, &resp->responseStatus, size) < 0) {
        WOLFSSL_LEAVE("OcspResponseDecode", ASN_PARSE_E);
        return ASN_PARSE_E;
    }

    if (resp->responseStatus != OCSP_SUCCESSFUL) {
        WOLFSSL_LEAVE("OcspResponseDecode", 0);
        return 0;
    }

    /* Next is an EXPLICIT record called ResponseBytes, OPTIONAL */
    if (idx >= size) {
        WOLFSSL_LEAVE("OcspResponseDecode", ASN_PARSE_E);
        return ASN_PARSE_E;
    }
    if (GetASNTag(source, &idx, &tag, size) < 0) {
        WOLFSSL_LEAVE("OcspResponseDecode", ASN_PARSE_E);
        return ASN_PARSE_E;
    }
    if (tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC)) {
        WOLFSSL_LEAVE("OcspResponseDecode", ASN_PARSE_E);
        return ASN_PARSE_E;
    }
    if (GetLength(source, &idx, &length, size) < 0) {
        WOLFSSL_LEAVE("OcspResponseDecode", ASN_PARSE_E);
        return ASN_PARSE_E;
    }

    /* Get the responseBytes SEQUENCE */
    if (GetSequence(source, &idx, &length, size) < 0) {
        WOLFSSL_LEAVE("OcspResponseDecode", ASN_PARSE_E);
        return ASN_PARSE_E;
    }

    /* Check ObjectID for the resposeBytes */
    if (GetObjectId(source, &idx, &oid, oidOcspType, size) < 0) {
        WOLFSSL_LEAVE("OcspResponseDecode", ASN_PARSE_E);
        return ASN_PARSE_E;
    }
    if (oid != OCSP_BASIC_OID) {
        WOLFSSL_LEAVE("OcspResponseDecode", ASN_PARSE_E);
        return ASN_PARSE_E;
    }
    ret = GetOctetString(source, &idx, &length, size);
    if (ret < 0) {
        WOLFSSL_LEAVE("OcspResponseDecode", ret);
        return ret;
    }

    ret = DecodeBasicOcspResponse(source, &idx, resp, size, cm, heap,
         noVerifyCert, noVerifySignature);
    if (ret < 0) {
        WOLFSSL_LEAVE("OcspResponseDecode", ret);
        return ret;
    }

    WOLFSSL_LEAVE("OcspResponseDecode", 0);
    return 0;
}

int EncodeOcspRequest(OcspRequest* req, byte* output, word32 size)
{
    byte seqArray[5][MAX_SEQ_SZ];
    /* The ASN.1 of the OCSP Request is an onion of sequences */
    byte algoArray[MAX_ALGO_SZ];
    byte issuerArray[MAX_ENCODED_DIG_SZ];
    byte issuerKeyArray[MAX_ENCODED_DIG_SZ];
    byte snArray[MAX_SN_SZ];
    byte extArray[MAX_OCSP_EXT_SZ];
    word32 seqSz[5], algoSz, issuerSz, issuerKeySz, extSz, totalSz;
    int i, snSz;
    int keyIdSz;

    WOLFSSL_ENTER("EncodeOcspRequest");

    algoSz = SetAlgoID(req->hashAlg, algoArray, oidHashType, 0);
    keyIdSz = wc_HashGetDigestSize(wc_OidGetHash(req->hashAlg));
    if (keyIdSz <= 0 || keyIdSz > WC_MAX_DIGEST_SIZE)
        return BAD_FUNC_ARG;

    issuerSz    = SetDigest(req->issuerHash,    keyIdSz,    issuerArray);
    issuerKeySz = SetDigest(req->issuerKeyHash, keyIdSz,    issuerKeyArray);
    snSz        = SetSerialNumber(req->serial,  req->serialSz, snArray,
                                                          MAX_SN_SZ, MAX_SN_SZ);
    extSz       = 0;

    if (snSz < 0)
        return snSz;

    if (req->nonceSz) {
        /* TLS Extensions use this function too - put extensions after
         * ASN.1: Context Specific [2].
         */
        extSz = EncodeOcspRequestExtensions(req, extArray + 2,
                                            OCSP_NONCE_EXT_SZ);
        extSz += SetExplicit(2, extSz, extArray, 0);
    }

    totalSz = algoSz + issuerSz + issuerKeySz + snSz;
    for (i = 4; i >= 0; i--) {
        seqSz[i] = SetSequence(totalSz, seqArray[i]);
        totalSz += seqSz[i];
        if (i == 2) totalSz += extSz;
    }

    if (output == NULL)
        return totalSz;
    if (totalSz > size)
        return BUFFER_E;

    totalSz = 0;
    for (i = 0; i < 5; i++) {
        XMEMCPY(output + totalSz, seqArray[i], seqSz[i]);
        totalSz += seqSz[i];
    }

    XMEMCPY(output + totalSz, algoArray, algoSz);
    totalSz += algoSz;

    XMEMCPY(output + totalSz, issuerArray, issuerSz);
    totalSz += issuerSz;

    XMEMCPY(output + totalSz, issuerKeyArray, issuerKeySz);
    totalSz += issuerKeySz;

    XMEMCPY(output + totalSz, snArray, snSz);
    totalSz += snSz;

    if (extSz != 0) {
        XMEMCPY(output + totalSz, extArray, extSz);
        totalSz += extSz;
    }

    return totalSz;
}

#ifdef HAVE_OCSP_RESPONDER
int DecodeOcspRequest(OcspRequest* req, const byte* input, word32 size)
{
    (void)req;
    (void)input;
    (void)size;
    /* Decoding ocsp requests not supported in legacy ASN parsing */
    return NOT_COMPILED_IN;
}

#endif
#endif
int GetNameHash_ex(const byte* source, word32* idx, byte* hash, int maxIdx,
    word32 sigOID)
{
    int    length;  /* length of all distinguished names */
    int    ret;
    word32 dummy;
    byte   tag;

    WOLFSSL_ENTER("GetNameHash");

    dummy = *idx;
    if (GetASNTag(source, &dummy, &tag, (word32)maxIdx) == 0 &&
            tag == ASN_OBJECT_ID) {
        WOLFSSL_MSG("Trying optional prefix...");

        if (GetLength(source, idx, &length, (word32)maxIdx) < 0)
            return ASN_PARSE_E;

        *idx += (word32)length;
        WOLFSSL_MSG("Got optional prefix");
    }

    /* For OCSP, RFC2560 section 4.1.1 states the issuer hash should be
     * calculated over the entire DER encoding of the Name field, including
     * the tag and length. */
    dummy = *idx;
    if (GetSequence(source, idx, &length, (word32)maxIdx) < 0)
        return ASN_PARSE_E;

    ret = CalcHashId_ex(source + dummy, (word32)length + *idx - dummy, hash,
        HashIdAlg(sigOID));

    *idx += (word32)length;

    return ret;
}

#if defined(HAVE_CRL) && !defined(WOLFCRYPT_ONLY)
static int GetRevoked(RevokedCert* rcert, const byte* buff, word32* idx,
                      DecodedCRL* dcrl, word32 maxIdx)
{
    int ret;
    int len;
    word32 end;
    RevokedCert* rc;
#ifdef CRL_STATIC_REVOKED_LIST
    int totalCerts = 0;
#endif
    WOLFSSL_ENTER("GetRevoked");

    if (GetSequence(buff, idx, &len, maxIdx) < 0)
        return ASN_PARSE_E;

    end = *idx + len;

#ifdef CRL_STATIC_REVOKED_LIST
    totalCerts = dcrl->totalCerts;

    if (totalCerts >= CRL_MAX_REVOKED_CERTS) {
        return MEMORY_E;
    }

    rc = &rcert[totalCerts];
    ret = wc_GetSerialNumber(buff, idx, rc->serialNumber, &rc->serialSz,maxIdx);
    if (ret < 0) {
        WOLFSSL_MSG("wc_GetSerialNumber error");
        return ret;
    }
#else

    rc = (RevokedCert*)XMALLOC(sizeof(RevokedCert), dcrl->heap,
                                                          DYNAMIC_TYPE_REVOKED);
    if (rc == NULL) {
        WOLFSSL_MSG("Alloc Revoked Cert failed");
        return MEMORY_E;
    }
    XMEMSET(rc, 0, sizeof(RevokedCert));
    ret = wc_GetSerialNumber(buff, idx, rc->serialNumber, &rc->serialSz,maxIdx);
    if (ret < 0) {
        WOLFSSL_MSG("wc_GetSerialNumber error");
        XFREE(rc, dcrl->heap, DYNAMIC_TYPE_REVOKED);
        return ret;
    }
    /* add to list */
    rc->next = dcrl->certs;
    dcrl->certs = rc;

    (void)rcert;
#endif /* CRL_STATIC_REVOKED_LIST */
    dcrl->totalCerts++;
    /* get date */
#ifndef NO_ASN_TIME
    ret = GetBasicDate(buff, idx, rc->revDate, &rc->revDateFormat, maxIdx);
    if (ret < 0) {
        WOLFSSL_MSG("Expecting Date");
        return ret;
    }
#endif
    /* Initialize reason code to absent */
    rc->reasonCode = -1;

    /* Parse CRL entry extensions if present */
    if (*idx < end) {
        word32 extIdx = *idx;
        int extLen;
        byte tag;

        /* Check for SEQUENCE tag (extensions wrapper) */
        if (GetASNTag(buff, &extIdx, &tag, end) == 0 &&
                tag == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
            word32 seqIdx = extIdx - 1;  /* back up to re-read tag */
            if (GetSequence(buff, &seqIdx, &extLen, end) >= 0) {
                word32 extEnd = seqIdx + (word32)extLen;

#if defined(OPENSSL_EXTRA)
                /* Store raw DER of extensions for OpenSSL compat API */
                {
                    word32 rawStart = *idx;
                    word32 rawLen = end - rawStart;
                    rc->extensions = (byte*)XMALLOC(rawLen, dcrl->heap,
                                                    DYNAMIC_TYPE_REVOKED);
                    if (rc->extensions != NULL) {
                        XMEMCPY(rc->extensions, buff + rawStart, rawLen);
                        rc->extensionsSz = rawLen;
                    }
                }
#endif

                ParseCRL_ReasonCode(buff, seqIdx, extEnd, &rc->reasonCode);
            }
        }
    }

    *idx = end;

    return 0;
}

/* Get CRL Signature, 0 on success */
static int GetCRL_Signature(const byte* source, word32* idx, DecodedCRL* dcrl,
                            int maxIdx)
{
    int    length;
    int    ret;

    WOLFSSL_ENTER("GetCRL_Signature");

    ret = CheckBitString(source, idx, &length, maxIdx, 1, NULL);
    if (ret != 0)
        return ret;
    dcrl->sigLength = length;

    dcrl->signature = (byte*)&source[*idx];
    *idx += dcrl->sigLength;

    return 0;
}

static int ParseCRL_CertList(RevokedCert* rcert, DecodedCRL* dcrl,
                           const byte* buf,word32* inOutIdx, int sz, int verify)
{
    word32 oid, dateIdx, idx, checkIdx;
    int length;
#ifdef WOLFSSL_NO_CRL_NEXT_DATE
    int doNextDate = 1;
#endif
    byte tag;

    if (dcrl == NULL || inOutIdx == NULL || buf == NULL) {
        return BAD_FUNC_ARG;
    }

    /* may have version */
    idx = *inOutIdx;

    checkIdx = idx;
    if (GetASNTag(buf, &checkIdx, &tag, sz) == 0 && tag == ASN_INTEGER) {
        if (GetMyVersion(buf, &idx, &dcrl->version, sz) < 0)
            return ASN_PARSE_E;
        dcrl->version++;
    }

    if (GetAlgoId(buf, &idx, &oid, oidIgnoreType, sz) < 0) {
        return ASN_PARSE_E;
    }
#ifdef WC_RSA_PSS
    else if (oid == CTC_RSASSAPSS) {
        word32 tmpSz;
        int len;

        tmpSz = idx;
        dcrl->sigParamsIndex = idx;
        if (GetSequence(buf, &idx, &len, sz) < 0) {
            dcrl->sigParamsIndex = 0;
            return ASN_PARSE_E;
        }
        idx += len;
        dcrl->sigParamsLength = idx - tmpSz;
    }
#endif

    checkIdx = idx;
    if (GetSequence(buf, &checkIdx, &length, sz) < 0) {
        return ASN_PARSE_E;
    }
#ifdef OPENSSL_EXTRA
    dcrl->issuerSz = length + (checkIdx - idx);
    dcrl->issuer   = (byte*)GetNameFromDer(buf + idx, (int)dcrl->issuerSz);
#endif

    if (GetNameHash_ex(buf, &idx, dcrl->issuerHash, sz, oid) < 0)
        return ASN_PARSE_E;

    if (GetBasicDate(buf, &idx, dcrl->lastDate, &dcrl->lastDateFormat, sz) < 0)
        return ASN_PARSE_E;

    dateIdx = idx;

    if (GetBasicDate(buf, &idx, dcrl->nextDate, &dcrl->nextDateFormat, sz) < 0)
    {
#ifndef WOLFSSL_NO_CRL_NEXT_DATE
        (void)dateIdx;
        return ASN_PARSE_E;
#else
        dcrl->nextDateFormat = ASN_OTHER_TYPE;  /* skip flag */
        doNextDate = 0;
        idx = dateIdx;
#endif
    }

#ifdef WOLFSSL_NO_CRL_NEXT_DATE
    if (doNextDate)
#endif
    {
#if !defined(NO_ASN_TIME) && !defined(WOLFSSL_NO_CRL_DATE_CHECK)
        if (verify != NO_VERIFY &&
            (! AsnSkipDateCheck) &&
            !XVALIDATE_DATE(dcrl->nextDate, dcrl->nextDateFormat, ASN_AFTER,
                            MAX_DATE_SIZE)) {
            WOLFSSL_MSG("CRL after date is no longer valid");
            WOLFSSL_ERROR_VERBOSE(CRL_CERT_DATE_ERR);
            return CRL_CERT_DATE_ERR;
        }
#else
        (void)verify;
#endif
    }

    checkIdx = idx;
    if ((idx != dcrl->sigIndex) && (GetASNTag(buf, &checkIdx, &tag, sz) == 0) &&
            (tag != CRL_EXTENSIONS)) {
        int len;
        word32 tlen;

        if (GetSequence(buf, &idx, &len, sz) < 0)
            return ASN_PARSE_E;
        tlen = (word32)len + idx;
        if (tlen < idx)
            return ASN_PARSE_E;

        while (idx < tlen) {
            if (GetRevoked(rcert, buf, &idx, dcrl, tlen) < 0)
                return ASN_PARSE_E;
        }
    }

    *inOutIdx = idx;

    return 0;
}

#ifndef NO_SKID
static int ParseCRL_AuthKeyIdExt(const byte* input, int sz, DecodedCRL* dcrl)
{
    word32 idx = 0;
    int length = 0, ret = 0;
    byte tag;

    WOLFSSL_ENTER("ParseCRL_AuthKeyIdExt");

    if (GetSequence(input, &idx, &length, sz) < 0) {
        WOLFSSL_MSG("\tfail: should be a SEQUENCE");
        return ASN_PARSE_E;
    }

    if (GetASNTag(input, &idx, &tag, sz) < 0) {
        return ASN_PARSE_E;
    }

    if (tag != (ASN_CONTEXT_SPECIFIC | 0)) {
        WOLFSSL_MSG("\tinfo: OPTIONAL item 0, not available");
        return 0;
    }

    if (GetLength(input, &idx, &length, sz) <= 0) {
        WOLFSSL_MSG("\tfail: extension data length");
        return ASN_PARSE_E;
    }

    dcrl->extAuthKeyIdSet = 1;

    /* Get the hash or hash of the hash if wrong size. */
    ret = GetHashId(input + idx, length, dcrl->extAuthKeyId,
        HashIdAlg(dcrl->signatureOID));

    return ret;
}

#endif
static int ParseCRL_Extensions(DecodedCRL* dcrl, const byte* buf,
        word32* inOutIdx, word32 sz)
{
    int length;
    word32 idx;
    word32 ext_bound; /* boundary index for the sequence of extensions */
    word32 oid;
    byte tag;

    WOLFSSL_ENTER("ParseCRL_Extensions");
    (void)dcrl;

    if (inOutIdx == NULL)
        return BAD_FUNC_ARG;

    idx = *inOutIdx;

    /* CRL Extensions are optional */
    if ((idx + 1) > sz)
        return 0;

    /* CRL Extensions are optional */
    if (GetASNTag(buf, &idx, &tag, sz) < 0)
        return 0;

    /* CRL Extensions are optional */
    if (tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
        return 0;

    if (GetLength(buf, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    if (GetSequence(buf, &idx, &length, sz) < 0)
        return ASN_PARSE_E;

    ext_bound = idx + length;

    while (idx < (word32)ext_bound) {
        word32 localIdx;
        int ret;
        int critical = 0;

        if (GetSequence(buf, &idx, &length, sz) < 0) {
            WOLFSSL_MSG("\tfail: should be a SEQUENCE");
            return ASN_PARSE_E;
        }

        oid = 0;
        if (GetObjectId(buf, &idx, &oid, oidCrlExtType, sz) < 0) {
            WOLFSSL_MSG("\tfail: OBJECT ID");
            return ASN_PARSE_E;
        }

        /* check for critical flag */
        if ((idx + 1) > (word32)sz) {
            WOLFSSL_MSG("\tfail: malformed buffer");
            return BUFFER_E;
        }

        localIdx = idx;
        if (GetASNTag(buf, &localIdx, &tag, sz) == 0 &&
                tag == ASN_BOOLEAN) {
            WOLFSSL_MSG("\tfound optional critical flag, moving past");
            ret = GetBoolean(buf, &idx, sz);
            if (ret < 0)
                return ret;
            critical = ret;
        }

        ret = GetOctetString(buf, &idx, &length, sz);
        if (ret < 0)
            return ret;

        if (oid == AUTH_KEY_OID) {
        #ifndef NO_SKID
            ret = ParseCRL_AuthKeyIdExt(buf + idx, length, dcrl);
            if (ret < 0) {
                WOLFSSL_MSG("\tcouldn't parse AuthKeyId extension");
                return ret;
            }
        #endif
        }
        else if (oid == CRL_NUMBER_OID) {
            localIdx = idx;
            if (GetASNTag(buf, &localIdx, &tag, sz) == 0 &&
                    tag == ASN_INTEGER) {
                word32 rawIdx = idx;
                int rawLen = 0;
                ret = GetASNInt(buf, &idx, &length, sz);
                if (ret < 0) {
                    WOLFSSL_MSG("\tcouldn't parse CRL number extension");
                    return ret;
                }
                /* RFC 5280 s5.2.3: CRL number must be non-negative.
                 * Check the raw encoding before GetASNInt strips
                 * the leading-zero pad: skip past the INTEGER tag
                 * and length, then reject if the first content byte
                 * has its high bit set (negative value). */
                (void)GetASNHeader(buf, ASN_INTEGER,
                    &rawIdx, &rawLen, sz);
                if (rawLen > 0 && (buf[rawIdx] & 0x80) != 0) {
                    WOLFSSL_MSG("CRL number is negative");
                    return ASN_PARSE_E;
                }
                if (length <= CRL_MAX_NUM_SZ) {
                    DECL_MP_INT_SIZE_DYN(m, CRL_MAX_NUM_SZ_BITS,
                                   CRL_MAX_NUM_SZ_BITS);
                    NEW_MP_INT_SIZE(m, CRL_MAX_NUM_SZ_BITS, NULL,
                                   DYNAMIC_TYPE_TMP_BUFFER);
                #ifdef MP_INT_SIZE_CHECK_NULL
                    if (m == NULL) {
                        ret = MEMORY_E;
                    }
                #endif

                    if (ret == 0 && ((ret = INIT_MP_INT_SIZE(m, CRL_MAX_NUM_SZ
                                    * CHAR_BIT)) != MP_OKAY)) {
                        ret = MP_INIT_E;
                    }

                    if (ret == MP_OKAY)
                        ret = mp_read_unsigned_bin(m, buf + idx, length);

                    if (ret != MP_OKAY)
                        ret = BUFFER_E;

                    if (ret == MP_OKAY && mp_toradix(m, (char*)dcrl->crlNumber,
                                MP_RADIX_HEX) != MP_OKAY)
                        ret = BUFFER_E;

                    if (ret == MP_OKAY) {
                        dcrl->crlNumberSet = 1;
                    }

                    FREE_MP_INT_SIZE(m, NULL, DYNAMIC_TYPE_TMP_BUFFER);

                    if (ret != MP_OKAY)
                        return ret;
                } else {
                    WOLFSSL_MSG("CRL number exceeds limitation");
                    ret = BUFFER_E;
                }
            }
        }
        else if (critical) {
            WOLFSSL_MSG("Unknown critical CRL extension");
            return ASN_CRIT_EXT_E;
        }

        idx += length;
    }

    *inOutIdx = idx;

    return 0;
}

int ParseCRL(RevokedCert* rcert, DecodedCRL* dcrl, const byte* buff, word32 sz,
             int verify, void* cm)
{
    Signer*      ca = NULL;
    SignatureCtx sigCtx;
    int          ret = 0;
    int          len;
    word32       idx = 0;
    const byte* sigParams = NULL;
    int sigParamsSz = 0;

    WOLFSSL_MSG("ParseCRL");

    /* raw crl hash */
    /* hash here if needed for optimized comparisons
     * wc_Sha sha;
     * wc_InitSha(&sha);
     * wc_ShaUpdate(&sha, buff, sz);
     * wc_ShaFinal(&sha, dcrl->crlHash); */

    if (GetSequence(buff, &idx, &len, sz) < 0)
        return ASN_PARSE_E;

    dcrl->certBegin = idx;
    /* Normalize sz for the length inside the outer sequence. */
    sz = len + idx;

    if (GetSequence(buff, &idx, &len, sz) < 0)
        return ASN_PARSE_E;
    dcrl->sigIndex = len + idx;

    if (ParseCRL_CertList(rcert, dcrl, buff, &idx, dcrl->sigIndex, verify) < 0)
        return ASN_PARSE_E;

    if (ParseCRL_Extensions(dcrl, buff, &idx, dcrl->sigIndex) < 0)
        return ASN_PARSE_E;

    idx = dcrl->sigIndex;

    if (GetAlgoId(buff, &idx, &dcrl->signatureOID, oidSigType, sz) < 0) {
        return ASN_PARSE_E;
    }
#ifdef WC_RSA_PSS
    else if (dcrl->signatureOID == CTC_RSASSAPSS) {
        word32 tmpSz;
        const byte* params;

        tmpSz = idx;
        params = buff + idx;
        if (GetSequence(buff, &idx, &len, sz) < 0) {
            return ASN_PARSE_E;
        }
        idx += len;
        sigParams = params;
        sigParamsSz = idx - tmpSz;
    }
#endif

    if (GetCRL_Signature(buff, &idx, dcrl, sz) < 0)
        return ASN_PARSE_E;

    /* openssl doesn't add skid by default for CRLs cause firefox chokes
       if experiencing issues uncomment NO_SKID define in CRL section of
       wolfssl/wolfcrypt/settings.h */
#ifndef NO_SKID
    if (dcrl->extAuthKeyIdSet) {
        ca = GetCA(cm, dcrl->extAuthKeyId); /* more unique than issuerHash */
    }
    if (ca != NULL && XMEMCMP(dcrl->issuerHash, ca->subjectNameHash,
            KEYID_SIZE) != 0) {
        ca = NULL;
    }
    if (ca == NULL) {
        ca = GetCAByName(cm, dcrl->issuerHash); /* last resort */
        /* If AKID is available then this CA doesn't have the public
         * key required */
        if (ca && dcrl->extAuthKeyIdSet) {
            WOLFSSL_MSG("CA SKID doesn't match AKID");
            ca = NULL;
        }
    }
#else
    ca = GetCA(cm, dcrl->issuerHash);
#endif /* !NO_SKID */
    WOLFSSL_MSG("About to verify CRL signature");

    if (ca == NULL) {
        WOLFSSL_MSG("Did NOT find CRL issuer CA");
        ret = ASN_CRL_NO_SIGNER_E;
        WOLFSSL_ERROR_VERBOSE(ret);
        goto end;
    }

    WOLFSSL_MSG("Found CRL issuer CA");
    ret = VerifyCRL_Signature(&sigCtx, buff + dcrl->certBegin,
           dcrl->sigIndex - dcrl->certBegin, dcrl->signature, dcrl->sigLength,
           dcrl->signatureOID, sigParams, sigParamsSz, ca, dcrl->heap);

end:
    return ret;
}

#endif
#ifdef WOLFSSL_CERT_PIV
int wc_ParseCertPIV(wc_CertPIV* piv, const byte* buf, word32 totalSz)
{
    int length = 0;
    word32 idx = 0;

    WOLFSSL_ENTER("wc_ParseCertPIV");

    if (piv == NULL || buf == NULL || totalSz == 0)
        return BAD_FUNC_ARG;

    XMEMSET(piv, 0, sizeof(wc_CertPIV));

    /* Detect Identiv PIV (with 0x0A, 0x0B and 0x0C sections) */
    /* Certificate (0A 82 05FA) */
    if (GetASNHeader(buf, ASN_PIV_CERT, &idx, &length, totalSz) >= 0) {
        /* Identiv Type PIV card */
        piv->isIdentiv = 1;

        piv->cert =   &buf[idx];
        piv->certSz = length;
        idx += length;

        /* Nonce (0B 14) */
        if (GetASNHeader(buf, ASN_PIV_NONCE, &idx, &length, totalSz) >= 0) {
            piv->nonce =   &buf[idx];
            piv->nonceSz = length;
            idx += length;
        }

        /* Signed Nonce (0C 82 0100) */
        if (GetASNHeader(buf, ASN_PIV_SIGNED_NONCE, &idx, &length, totalSz) >= 0) {
            piv->signedNonce =   &buf[idx];
            piv->signedNonceSz = length;
        }

        idx = 0;
        buf = piv->cert;
        totalSz = piv->certSz;
    }

    /* Certificate Buffer Total Size (53 82 05F6) */
    if (GetASNHeader(buf, ASN_APPLICATION | ASN_PRINTABLE_STRING, &idx,
                                                   &length, totalSz) < 0) {
        return ASN_PARSE_E;
    }
    /* PIV Certificate (70 82 05ED) */
    if (GetASNHeader(buf, ASN_PIV_TAG_CERT, &idx, &length,
                                                         totalSz) < 0) {
        return ASN_PARSE_E;
    }

    /* Capture certificate buffer pointer and length */
    piv->cert =   &buf[idx];
    piv->certSz = length;
    idx += length;

    /* PIV Certificate Info (71 01 00) */
    if (GetASNHeader(buf, ASN_PIV_TAG_CERT_INFO, &idx, &length,
                                                        totalSz) >= 0) {
        if (length >= 1) {
            piv->compression = (buf[idx] & ASN_PIV_CERT_INFO_COMPRESSED);
            piv->isX509 =      ((buf[idx] & ASN_PIV_CERT_INFO_ISX509) != 0);
        }
        idx += length;
    }

    /* PIV Error Detection (FE 00) */
    if (GetASNHeader(buf, ASN_PIV_TAG_ERR_DET, &idx, &length,
                                                        totalSz) >= 0) {
        piv->certErrDet =   &buf[idx];
        piv->certErrDetSz = length;
        idx += length;
    }

    return 0;
}

#endif

#endif /* WOLFSSL_ASN_ORIG_INCLUDED */
