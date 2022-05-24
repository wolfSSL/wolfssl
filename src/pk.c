/* pk.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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


#if !defined(WOLFSSL_PK_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning pk.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif

/*******************************************************************************
 * COMMON FUNCTIONS
 ******************************************************************************/
#if !defined(NO_CERTS) && defined(OPENSSL_EXTRA)
#if defined(XFPRINTF) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM) && (!defined(NO_RSA) || !defined(NO_DSA) || \
    defined(HAVE_ECC))
/* Print the number bn in hex with name field and indentation indent to file fp.
 * Used by wolfSSL_DSA_print_fp and wolfSSL_RSA_print_fp to print DSA and RSA
 * keys and parameters.
 */
static int PrintBNFieldFp(XFILE fp, int indent, const char* field,
                          const WOLFSSL_BIGNUM* bn)
{
    static const int HEX_INDENT = 4;
    static const int MAX_DIGITS_PER_LINE = 30;

    int ret = WOLFSSL_SUCCESS;
    int i = 0;
    char* buf = NULL;

    if (fp == XBADFILE || indent < 0 || field == NULL || bn == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == WOLFSSL_SUCCESS) {
        buf = wolfSSL_BN_bn2hex(bn);
        if (buf == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }
    if (ret == WOLFSSL_SUCCESS) {
        XFPRINTF(fp, "%*s", indent, "");
        XFPRINTF(fp, "%s:\n", field);
        XFPRINTF(fp, "%*s", indent + HEX_INDENT, "");
        while (buf[i]) {
            if (i != 0) {
                if (i % 2 == 0) {
                    XFPRINTF(fp, ":");
                }
                if (i % MAX_DIGITS_PER_LINE == 0) {
                    XFPRINTF(fp, "\n");
                    XFPRINTF(fp, "%*s", indent + HEX_INDENT, "");
                }
            }
            XFPRINTF(fp, "%c", buf[i++]);
        }
        XFPRINTF(fp, "\n");
    }

    if (buf != NULL) {
        XFREE(buf, NULL, DYNAMIC_TYPE_OPENSSL);
    }

    return ret;
}
#endif /* XFPRINTF && !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM && (!NO_DSA ||
          !NO_RSA || HAVE_ECC)*/
#endif /* !NO_CERTS && OPENSSL_EXTRA */


/*******************************************************************************
 * START OF RSA API
 ******************************************************************************/

#ifndef NO_RSA

#if defined(OPENSSL_EXTRA) && !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA)
WC_RNG* WOLFSSL_RSA_GetRNG(WOLFSSL_RSA *rsa, WC_RNG **tmpRNG, int *initTmpRng)
{
    WC_RNG* rng = NULL;

    if (!rsa || !initTmpRng) {
        return NULL;
    }
    *initTmpRng = 0;

#if !defined(HAVE_FIPS) && !defined(HAVE_USER_RSA) && \
    !defined(HAVE_FAST_RSA) && defined(WC_RSA_BLINDING)
    rng = ((RsaKey*)rsa->internal)->rng;
#endif
    if (tmpRNG != NULL
    #if !defined(HAVE_FIPS) && !defined(HAVE_USER_RSA) && \
        !defined(HAVE_FAST_RSA) && defined(WC_RSA_BLINDING)
        && rng == NULL
    #endif
        ) {
        if (*tmpRNG == NULL) {
#ifdef WOLFSSL_SMALL_STACK
            *tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (*tmpRNG == NULL)
                return NULL;
#else
            WOLFSSL_MSG("*tmpRNG is null");
            return NULL;
#endif
        }

        if (wc_InitRng(*tmpRNG) == 0) {
            rng = *tmpRNG;
            *initTmpRng = 1;
        }
        else {
            WOLFSSL_MSG("Bad RNG Init, trying global");
            rng = wolfssl_get_global_rng();
#ifdef WOLFSSL_SMALL_STACK
            if (*tmpRNG)
                XFREE(*tmpRNG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            *tmpRNG = NULL;
#endif
        }
    }
    return rng;
}
#endif

#ifdef OPENSSL_EXTRA

/* return wolfSSL native error codes. */
static int wolfSSL_RSA_generate_key_native(WOLFSSL_RSA* rsa, int bits,
    WOLFSSL_BIGNUM* bn, void* cb)
{
    int ret;

    (void)cb;
    (void)bn;
    (void)bits;

    WOLFSSL_ENTER("wolfSSL_RSA_generate_key_native");

    if (rsa == NULL || rsa->internal == NULL) {
        /* bit size checked during make key call */
        WOLFSSL_MSG("bad arguments");
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_KEY_GEN
    {
    #ifdef WOLFSSL_SMALL_STACK
        WC_RNG* rng;
    #else
        WC_RNG  rng[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
        if (rng == NULL)
            return MEMORY_E;
    #endif

        if ((ret = wc_InitRng(rng)) < 0)
            WOLFSSL_MSG("RNG init failed");
        else if ((ret = wc_MakeRsaKey((RsaKey*)rsa->internal, bits,
                    wolfSSL_BN_get_word(bn), rng)) != MP_OKAY)
            WOLFSSL_MSG("wc_MakeRsaKey failed");
        else if ((ret = SetRsaExternal(rsa)) != WOLFSSL_SUCCESS)
            WOLFSSL_MSG("SetRsaExternal failed");
        else {
            rsa->inSet = 1;
            ret = WOLFSSL_ERROR_NONE;
        }

        wc_FreeRng(rng);
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(rng, NULL, DYNAMIC_TYPE_RNG);
    #endif
    }
#else
    WOLFSSL_MSG("No Key Gen built in");
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}

/* Generates a RSA key of length len
 *
 * len  length of RSA key i.e. 2048
 * e    e to use when generating RSA key
 * f    callback function for generation details
 * data user callback argument
 *
 * Note: Because of wc_MakeRsaKey an RSA key size generated can be slightly
 *       rounded down. For example generating a key of size 2999 with e =
 *       65537 will make a key of size 374 instead of 375.
 * Returns a new RSA key on success and NULL on failure
 */
WOLFSSL_RSA* wolfSSL_RSA_generate_key(int len, unsigned long e,
                                      void(*f)(int, int, void*), void* data)
{
    WOLFSSL_RSA*    rsa = NULL;
    WOLFSSL_BIGNUM* bn  = NULL;

    WOLFSSL_ENTER("wolfSSL_RSA_generate_key");

    (void)f;
    (void)data;

    if (len < 0) {
        WOLFSSL_MSG("Bad argument: length was less than 0");
        return NULL;
    }

    bn = wolfSSL_BN_new();
    if (bn == NULL) {
        WOLFSSL_MSG("Error creating big number");
        return NULL;
    }

    if (wolfSSL_BN_set_word(bn, e) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error using e value");
        wolfSSL_BN_free(bn);
        return NULL;
    }

    rsa = wolfSSL_RSA_new();
    if (rsa == NULL) {
        WOLFSSL_MSG("memory error");
    }
    else {
#ifdef HAVE_FIPS
        for (;;)
#endif
        {
            int gen_ret = wolfSSL_RSA_generate_key_native(rsa, len, bn, NULL);
            if (gen_ret != WOLFSSL_ERROR_NONE) {
#ifdef HAVE_FIPS
                if (gen_ret == PRIME_GEN_E)
                    continue;
#endif
                wolfSSL_RSA_free(rsa);
                rsa = NULL;
            }
#ifdef HAVE_FIPS
            break;
#endif
        }
    }
    wolfSSL_BN_free(bn);

    return rsa;
}

/* return compliant with OpenSSL
 *   1 if success, 0 if error
 */
int wolfSSL_RSA_generate_key_ex(WOLFSSL_RSA* rsa, int bits, WOLFSSL_BIGNUM* bn,
                                void* cb)
{
#ifdef HAVE_FIPS
    for (;;)
#endif
    {
        int gen_ret = wolfSSL_RSA_generate_key_native(rsa, bits, bn, cb);
        if (gen_ret == WOLFSSL_ERROR_NONE)
            return WOLFSSL_SUCCESS;
#ifdef HAVE_FIPS
        else if (gen_ret == PRIME_GEN_E)
            continue;
#endif
        else
            return WOLFSSL_FAILURE;
    }
}

#if !defined(HAVE_USER_RSA)

#ifdef DEBUG_SIGN
static void DEBUG_SIGN_msg(const char *title, const unsigned char *out,
    unsigned int outlen)
{
    const unsigned char *pt;
    printf("%s[%d] = \n", title, (int)outlen);
    outlen = outlen>100?100:outlen;
    for (pt = out; pt < out + outlen;
            printf("%c", ((*pt)&0x6f)>='A'?((*pt)&0x6f):'.'), pt++);
    printf("\n");
}
#else
#define DEBUG_SIGN_msg(a,b,c)
#endif

static int nid2HashSum(int type) {
    switch (type) {
    #ifdef WOLFSSL_MD2
        case NID_md2:       type = MD2h;    break;
    #endif
    #ifndef NO_MD5
        case NID_md5:       type = MD5h;    break;
    #endif
    #ifndef NO_SHA
        case NID_sha1:      type = SHAh;    break;
    #endif
    #ifndef NO_SHA256
        case NID_sha256:    type = SHA256h; break;
    #endif
    #ifdef WOLFSSL_SHA384
        case NID_sha384:    type = SHA384h; break;
    #endif
    #ifdef WOLFSSL_SHA512
        case NID_sha512:    type = SHA512h; break;
    #endif
    #ifndef WOLFSSL_NOSHA3_224
        case NID_sha3_224:  type = SHA3_224h; break;
    #endif
    #ifndef WOLFSSL_NOSHA3_256
        case NID_sha3_256:  type = SHA3_256h; break;
    #endif
    #ifndef WOLFSSL_NOSHA3_384
        case NID_sha3_384:  type = SHA3_384h; break;
    #endif
    #ifndef WOLFSSL_NOSHA3_512
        case NID_sha3_512:  type = SHA3_512h; break;
    #endif
        default:
            WOLFSSL_MSG("This NID (md type) not configured or not implemented");
            return 0;
    }
    return type;
}

/* return WOLFSSL_SUCCESS on ok, 0 otherwise */
int wolfSSL_RSA_sign(int type, const unsigned char* m,
                           unsigned int mLen, unsigned char* sigRet,
                           unsigned int* sigLen, WOLFSSL_RSA* rsa)
{
    return wolfSSL_RSA_sign_ex(type, m, mLen, sigRet, sigLen, rsa, 1);
}

int wolfSSL_RSA_sign_ex(int type, const unsigned char* m,
                           unsigned int mLen, unsigned char* sigRet,
                           unsigned int* sigLen, WOLFSSL_RSA* rsa, int flag)
{
    if (sigLen != NULL)
        *sigLen = RSA_MAX_SIZE / CHAR_BIT; /* No size checking in this API */
    return wolfSSL_RSA_sign_generic_padding(type, m, mLen, sigRet, sigLen,
            rsa, flag, RSA_PKCS1_PADDING);
}

/**
 * Sign a message with the chosen message digest, padding, and RSA key.
 * @param type      Hash NID
 * @param m         Message to sign. Most likely this will be the digest of
 *                  the message to sign
 * @param mLen      Length of message to sign
 * @param sigRet    Output buffer
 * @param sigLen    On Input: length of sigRet buffer
 *                  On Output: length of data written to sigRet
 * @param rsa       RSA key used to sign the input
 * @param flag      1: Output the signature
 *                  0: Output the value that the unpadded signature should be
 *                     compared to. Note: for RSA_PKCS1_PSS_PADDING the
 *                     wc_RsaPSS_CheckPadding_ex function should be used to check
 *                     the output of a *Verify* function.
 * @param padding   Padding to use. Only RSA_PKCS1_PSS_PADDING and
 *                  RSA_PKCS1_PADDING are currently supported for signing.
 * @return          WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on error
 */
int wolfSSL_RSA_sign_generic_padding(int type, const unsigned char* m,
                           unsigned int mLen, unsigned char* sigRet,
                           unsigned int* sigLen, WOLFSSL_RSA* rsa, int flag,
                           int padding)
{
    word32  outLen;
    word32  signSz;
    int     initTmpRng = 0;
    WC_RNG* rng        = NULL;
    int     ret        = 0;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRNG     = NULL;
    byte*   encodedSig = NULL;
#else
    WC_RNG  tmpRNG[1];
    byte    encodedSig[MAX_ENCODED_SIG_SZ];
#endif

    WOLFSSL_ENTER("wolfSSL_RSA_sign_generic_padding");

    if (m == NULL || sigRet == NULL || sigLen == NULL || rsa == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }
    DEBUG_SIGN_msg("Message to Sign", m, mLen);

    if (rsa->inSet == 0) {
        WOLFSSL_MSG("No RSA internal set, do it");

        if (SetRsaInternal(rsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetRsaInternal failed");
            return WOLFSSL_FAILURE;
        }
    }

    type = nid2HashSum(type);

    outLen = (word32)wolfSSL_BN_num_bytes(rsa->n);

#ifdef WOLFSSL_SMALL_STACK
    tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
    if (tmpRNG == NULL)
        return WOLFSSL_FAILURE;

    encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL,
                                                   DYNAMIC_TYPE_SIGNATURE);
    if (encodedSig == NULL) {
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
        return WOLFSSL_FAILURE;
    }
#endif

    if (outLen == 0) {
        WOLFSSL_MSG("Bad RSA size");
    }
    else if (outLen > *sigLen) {
        WOLFSSL_MSG("Output buffer too small");
        return WOLFSSL_FAILURE;
    }
    else if (wc_InitRng(tmpRNG) == 0) {
        rng = tmpRNG;
        initTmpRng = 1;
    }
    else {
        WOLFSSL_MSG("Bad RNG Init, trying global");

        rng = wolfssl_get_global_rng();
    }

    if (rng) {
        if (flag != 0) {
            switch (padding) {
#ifdef WC_RSA_NO_PADDING
            case RSA_NO_PADDING:
                WOLFSSL_MSG("RSA_NO_PADDING not supported for signing");
                ret = BAD_FUNC_ARG;
                break;
#endif
#if defined(WC_RSA_PSS) && !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,1)))
            case RSA_PKCS1_PSS_PADDING:
            {
                enum wc_HashType hType = wc_OidGetHash(type);
#ifndef WOLFSSL_PSS_SALT_LEN_DISCOVER
                WOLFSSL_MSG("Using RSA-PSS with hash length salt. "
                            "OpenSSL uses max length by default.");
#endif
                ret = wc_RsaPSS_Sign_ex(m, mLen, sigRet, outLen,
                        hType, wc_hash2mgf(hType),
#ifndef WOLFSSL_PSS_SALT_LEN_DISCOVER
                        RSA_PSS_SALT_LEN_DEFAULT,
#else
                        RSA_PSS_SALT_LEN_DISCOVER,
#endif
                        (RsaKey*)rsa->internal, rng);
                break;
            }
#endif
#ifndef WC_NO_RSA_OAEP
            case RSA_PKCS1_OAEP_PADDING:
            {
                WOLFSSL_MSG("RSA_PKCS1_OAEP_PADDING not supported for signing");
                ret = BAD_FUNC_ARG;
                break;
            }
#endif
            case RSA_PKCS1_PADDING:
                signSz = wc_EncodeSignature(encodedSig, m, mLen, type);
                if (signSz == 0) {
                    WOLFSSL_MSG("Bad Encode Signature");
                }
                DEBUG_SIGN_msg("Encoded Message", encodedSig, signSz);
                ret = wc_RsaSSL_Sign(encodedSig, signSz, sigRet, outLen,
                                (RsaKey*)rsa->internal, rng);
                break;
            default:
                WOLFSSL_MSG("Unsupported padding");
                ret = BAD_FUNC_ARG;
                break;
            }
            if (ret <= 0) {
                WOLFSSL_MSG("Bad Rsa Sign");
                ret = 0;
            }
            else {
                *sigLen = (unsigned int)ret;
                ret = WOLFSSL_SUCCESS;
                DEBUG_SIGN_msg("Signature", sigRet, *sigLen);
            }
        } else {
            switch (padding) {
            case RSA_NO_PADDING:
            case RSA_PKCS1_PSS_PADDING:
            case RSA_PKCS1_OAEP_PADDING:
                ret = WOLFSSL_SUCCESS;
                XMEMCPY(sigRet, m, mLen);
                *sigLen = mLen;
                break;
            case RSA_PKCS1_PADDING:
            default:
                signSz = wc_EncodeSignature(encodedSig, m, mLen, type);
                if (signSz == 0) {
                    WOLFSSL_MSG("Bad Encode Signature");
                }
                ret = WOLFSSL_SUCCESS;
                XMEMCPY(sigRet, encodedSig, signSz);
                *sigLen = signSz;
                break;
            }
        }
    }

    if (initTmpRng)
        wc_FreeRng(tmpRNG);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpRNG,     NULL, DYNAMIC_TYPE_RNG);
    XFREE(encodedSig, NULL, DYNAMIC_TYPE_SIGNATURE);
#endif

    if (ret == WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_RSA_sign_generic_padding success");
    }
    else {
        WOLFSSL_LEAVE("wolfSSL_RSA_sign_generic_padding", ret);
        WOLFSSL_MSG("wolfSSL_RSA_sign_generic_padding failed. "
                    "Returning WOLFSSL_FAILURE.");
        ret = WOLFSSL_FAILURE;
    }
    return ret;
}

/* returns WOLFSSL_SUCCESS on successful verify and WOLFSSL_FAILURE on fail */
int wolfSSL_RSA_verify(int type, const unsigned char* m,
                               unsigned int mLen, const unsigned char* sig,
                               unsigned int sigLen, WOLFSSL_RSA* rsa)
{
    return wolfSSL_RSA_verify_ex(type, m, mLen, sig, sigLen, rsa,
        RSA_PKCS1_PADDING);
}

/* returns WOLFSSL_SUCCESS on successful verify and WOLFSSL_FAILURE on fail */
int wolfSSL_RSA_verify_ex(int type, const unsigned char* m,
                               unsigned int mLen, const unsigned char* sig,
                               unsigned int sigLen, WOLFSSL_RSA* rsa,
                               int padding) {
    int     ret = WOLFSSL_FAILURE;
    unsigned char *sigRet = NULL;
    unsigned char *sigDec = NULL;
    unsigned int   len = sigLen;
    int verLen;
#if (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && \
    FIPS_VERSION_GE(5,1))) && !defined(HAVE_SELFTEST)
    int hSum = nid2HashSum(type);
    enum wc_HashType hType;
#endif

    WOLFSSL_ENTER("wolfSSL_RSA_verify");
    if ((m == NULL) || (sig == NULL)) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }
    sigDec = (unsigned char *)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sigDec == NULL) {
        WOLFSSL_MSG("Memory failure");
        goto cleanup;
    }
    if (padding != RSA_PKCS1_PSS_PADDING) {
        sigRet = (unsigned char *)XMALLOC(sigLen, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (sigRet == NULL) {
            WOLFSSL_MSG("Memory failure");
            goto cleanup;
        }
        /* get non-encrypted signature to be compared with decrypted signature */
        if (wolfSSL_RSA_sign_generic_padding(type, m, mLen, sigRet, &len, rsa,
                0, padding) <= 0) {
            WOLFSSL_MSG("Message Digest Error");
            goto cleanup;
        }
        DEBUG_SIGN_msg("Encoded Message", sigRet, len);
    }
    else {
        DEBUG_SIGN_msg("Encoded Message", m, mLen);
    }
    /* decrypt signature */
#if (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && \
    FIPS_VERSION_GE(5,1))) && !defined(HAVE_SELFTEST)
    hType = wc_OidGetHash(hSum);
    if ((verLen = wc_RsaSSL_Verify_ex2(sig, sigLen, (unsigned char *)sigDec,
            sigLen, (RsaKey*)rsa->internal, padding, hType)) <= 0) {
        WOLFSSL_MSG("RSA Decrypt error");
        goto cleanup;
    }
#else
    verLen = wc_RsaSSL_Verify(sig, sigLen, (unsigned char *)sigDec, sigLen,
        (RsaKey*)rsa->internal);
#endif
    DEBUG_SIGN_msg("Decrypted Signature", sigDec, ret);
#if defined(WC_RSA_PSS) && !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,1)))
    if (padding == RSA_PKCS1_PSS_PADDING) {
        if (wc_RsaPSS_CheckPadding_ex(m, mLen, sigDec, verLen,
                hType,
#ifndef WOLFSSL_PSS_SALT_LEN_DISCOVER
                RSA_PSS_SALT_LEN_DEFAULT,
#else
                RSA_PSS_SALT_LEN_DISCOVER,
#endif
                mp_count_bits(&((RsaKey*)rsa->internal)->n)) != 0) {
            WOLFSSL_MSG("wc_RsaPSS_CheckPadding_ex error");
            goto cleanup;
        }
    }
    else
#endif /* !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) */
    if ((int)len != verLen || XMEMCMP(sigRet, sigDec, verLen) != 0) {
        WOLFSSL_MSG("wolfSSL_RSA_verify_ex failed");
        goto cleanup;
    }

    WOLFSSL_MSG("wolfSSL_RSA_verify_ex success");
    ret = WOLFSSL_SUCCESS;
cleanup:
    if (sigRet)
        XFREE(sigRet, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sigDec)
        XFREE(sigDec, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

void wolfSSL_RSA_get0_crt_params(const WOLFSSL_RSA *r,
        const WOLFSSL_BIGNUM **dmp1, const WOLFSSL_BIGNUM **dmq1,
        const WOLFSSL_BIGNUM **iqmp)
{
    WOLFSSL_ENTER("wolfSSL_RSA_get0_crt_params");

    if (r != NULL) {
        if (dmp1 != NULL)
            *dmp1 = r->dmp1;
        if (dmq1 != NULL)
            *dmq1 = r->dmq1;
        if (iqmp != NULL)
            *iqmp = r->iqmp;
    } else {
        if (dmp1 != NULL)
            *dmp1 = NULL;
        if (dmq1 != NULL)
            *dmq1 = NULL;
        if (iqmp != NULL)
            *iqmp = NULL;
    }
}

int wolfSSL_RSA_set0_crt_params(WOLFSSL_RSA *r, WOLFSSL_BIGNUM *dmp1,
                                WOLFSSL_BIGNUM *dmq1, WOLFSSL_BIGNUM *iqmp)
{
    WOLFSSL_ENTER("wolfSSL_RSA_set0_crt_params");

    /* If a param is null in r then it must be non-null in the
     * corresponding user input. */
    if (r == NULL || (r->dmp1 == NULL && dmp1 == NULL) ||
            (r->dmq1 == NULL && dmq1 == NULL) ||
            (r->iqmp == NULL && iqmp == NULL)) {
        WOLFSSL_MSG("Bad parameters");
        return WOLFSSL_FAILURE;
    }

    if (dmp1 != NULL) {
        wolfSSL_BN_clear_free(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL) {
        wolfSSL_BN_clear_free(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL) {
        wolfSSL_BN_clear_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return SetRsaInternal(r) == WOLFSSL_SUCCESS ?
            WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}

void wolfSSL_RSA_get0_factors(const WOLFSSL_RSA *r, const WOLFSSL_BIGNUM **p,
                              const WOLFSSL_BIGNUM **q)
{
    WOLFSSL_ENTER("wolfSSL_RSA_get0_factors");

    if (r != NULL) {
        if (p != NULL)
            *p = r->p;
        if (q != NULL)
            *q = r->q;
    } else {
        if (p != NULL)
            *p = NULL;
        if (q != NULL)
            *q = NULL;
    }
}

int wolfSSL_RSA_set0_factors(WOLFSSL_RSA *r, WOLFSSL_BIGNUM *p,
    WOLFSSL_BIGNUM *q)
{
    WOLFSSL_ENTER("wolfSSL_RSA_set0_factors");

    /* If a param is null in r then it must be non-null in the
     * corresponding user input. */
    if (r == NULL || (r->p == NULL && p == NULL) ||
            (r->q == NULL && q == NULL)) {
        WOLFSSL_MSG("Bad parameters");
        return WOLFSSL_FAILURE;
    }

    if (p != NULL) {
        wolfSSL_BN_clear_free(r->p);
        r->p = p;
    }
    if (q != NULL) {
        wolfSSL_BN_clear_free(r->q);
        r->q = q;
    }

    return SetRsaInternal(r) == WOLFSSL_SUCCESS ?
            WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}

void wolfSSL_RSA_get0_key(const WOLFSSL_RSA *r, const WOLFSSL_BIGNUM **n,
    const WOLFSSL_BIGNUM **e, const WOLFSSL_BIGNUM **d)
{
    WOLFSSL_ENTER("wolfSSL_RSA_get0_key");

    if (r != NULL) {
        if (n != NULL)
            *n = r->n;
        if (e != NULL)
            *e = r->e;
        if (d != NULL)
            *d = r->d;
    } else {
        if (n != NULL)
            *n = NULL;
        if (e != NULL)
            *e = NULL;
        if (d != NULL)
            *d = NULL;
    }
}

/* generate p-1 and q-1, WOLFSSL_SUCCESS on ok */
int wolfSSL_RSA_GenAdd(WOLFSSL_RSA* rsa)
{
    int    err;
    mp_int tmp;

    WOLFSSL_MSG("wolfSSL_RsaGenAdd");

    if (rsa == NULL || rsa->p == NULL || rsa->q == NULL || rsa->d == NULL ||
                       rsa->dmp1 == NULL || rsa->dmq1 == NULL) {
        WOLFSSL_MSG("rsa no init error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (mp_init(&tmp) != MP_OKAY) {
        WOLFSSL_MSG("mp_init error");
        return WOLFSSL_FATAL_ERROR;
    }

    err = mp_sub_d((mp_int*)rsa->p->internal, 1, &tmp);
    if (err != MP_OKAY) {
        WOLFSSL_MSG("mp_sub_d error");
    }
    else
        err = mp_mod((mp_int*)rsa->d->internal, &tmp,
                     (mp_int*)rsa->dmp1->internal);

    if (err != MP_OKAY) {
        WOLFSSL_MSG("mp_mod error");
    }
    else
        err = mp_sub_d((mp_int*)rsa->q->internal, 1, &tmp);
    if (err != MP_OKAY) {
        WOLFSSL_MSG("mp_sub_d error");
    }
    else
        err = mp_mod((mp_int*)rsa->d->internal, &tmp,
                     (mp_int*)rsa->dmq1->internal);

    mp_clear(&tmp);

    if (err == MP_OKAY)
        return WOLFSSL_SUCCESS;
    else
        return WOLFSSL_FATAL_ERROR;
}

#endif /* !HAVE_USER_RSA */

#if defined(WOLFSSL_KEY_GEN) && !defined(HAVE_USER_RSA)
int wolfSSL_RSA_To_Der(WOLFSSL_RSA* rsa, byte** outBuf, int publicKey,
    void* heap)
{
    int derSz  = 0;
    int ret;
    byte* derBuf;

    WOLFSSL_ENTER("wolfSSL_RSA_To_Der");

    if (!rsa || (publicKey != 0 && publicKey != 1)) {
        WOLFSSL_LEAVE("wolfSSL_RSA_To_Der", BAD_FUNC_ARG);
        return BAD_FUNC_ARG;
    }

    if (rsa->inSet == 0) {
        if ((ret = SetRsaInternal(rsa)) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetRsaInternal() Failed");
            WOLFSSL_LEAVE("wolfSSL_RSA_To_Der", ret);
            return ret;
        }
    }

    if (publicKey) {
        if ((derSz = wc_RsaPublicKeyDerSize((RsaKey *)rsa->internal, 1)) < 0) {
            WOLFSSL_MSG("wc_RsaPublicKeyDerSize failed");
            WOLFSSL_LEAVE("wolfSSL_RSA_To_Der", derSz);
            return derSz;
        }
    }
    else {
        if ((derSz = wc_RsaKeyToDer((RsaKey*)rsa->internal, NULL, 0)) < 0) {
            WOLFSSL_MSG("wc_RsaKeyToDer failed");
            WOLFSSL_LEAVE("wolfSSL_RSA_To_Der", derSz);
            return derSz;
        }
    }

    if (outBuf) {
        if (!(derBuf = (byte*)XMALLOC(derSz, heap, DYNAMIC_TYPE_TMP_BUFFER))) {
            WOLFSSL_MSG("malloc failed");
            WOLFSSL_LEAVE("wolfSSL_RSA_To_Der", MEMORY_ERROR);
            return MEMORY_ERROR;
        }

        /* Key to DER */
        if (publicKey) {
            derSz = wc_RsaKeyToPublicDer((RsaKey*)rsa->internal, derBuf, derSz);
        }
        else {
            derSz = wc_RsaKeyToDer((RsaKey*)rsa->internal, derBuf, derSz);
        }

        if (derSz < 0) {
            WOLFSSL_MSG("wc_RsaKeyToPublicDer failed");
            XFREE(derBuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        else {
            if (*outBuf) {
                XMEMCPY(*outBuf, derBuf, derSz);
                XFREE(derBuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
            }
            else {
                *outBuf = derBuf;
            }
        }
    }

    (void)heap; /* unused if memory is disabled */
    WOLFSSL_LEAVE("wolfSSL_RSA_To_Der", derSz);
    return derSz;
}
#endif

#ifndef NO_BIO
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
/* Takes a WOLFSSL_RSA key and writes it out to a WOLFSSL_BIO
 *
 * bio    the WOLFSSL_BIO to write to
 * key    the WOLFSSL_RSA key to write out
 * cipher cipher used
 * passwd password string if used
 * len    length of password string
 * cb     password callback to use
 * arg    null terminated string for passphrase
 */
int wolfSSL_PEM_write_bio_RSAPrivateKey(WOLFSSL_BIO* bio, WOLFSSL_RSA* key,
                                        const WOLFSSL_EVP_CIPHER* cipher,
                                        unsigned char* passwd, int len,
                                        wc_pem_password_cb* cb, void* arg)
{
    int ret;
    WOLFSSL_EVP_PKEY* pkey;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_RSAPrivateKey");

    if (bio == NULL || key == NULL) {
        WOLFSSL_MSG("Bad Function Arguments");
        return WOLFSSL_FAILURE;
    }

    pkey = wolfSSL_EVP_PKEY_new_ex(bio->heap);
    if (pkey == NULL) {
        WOLFSSL_MSG("wolfSSL_EVP_PKEY_new_ex failed");
        return WOLFSSL_FAILURE;
    }

    pkey->type   = EVP_PKEY_RSA;
    pkey->rsa    = key;
    pkey->ownRsa = 0;
#if defined(WOLFSSL_KEY_GEN) && !defined(HAVE_USER_RSA)
    /* similar to how wolfSSL_PEM_write_mem_RSAPrivateKey finds DER of key */
    {
        int derSz;
        byte* derBuf = NULL;

        if ((derSz = wolfSSL_RSA_To_Der(key, &derBuf, 0, bio->heap)) < 0) {
            WOLFSSL_MSG("wolfSSL_RSA_To_Der failed");
            return WOLFSSL_FAILURE;
        }

        if (derBuf == NULL) {
            WOLFSSL_MSG("wolfSSL_RSA_To_Der failed to get buffer");
            return WOLFSSL_FAILURE;
        }

        pkey->pkey.ptr = (char*)XMALLOC(derSz, bio->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (pkey->pkey.ptr == NULL) {
            WOLFSSL_MSG("key malloc failed");
            XFREE(derBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_EVP_PKEY_free(pkey);
            return WOLFSSL_FAILURE;
        }
        pkey->pkey_sz = derSz;
        XMEMCPY(pkey->pkey.ptr, derBuf, derSz);
        XFREE(derBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif /* WOLFSSL_KEY_GEN && !HAVE_USER_RSA */

    ret = wolfSSL_PEM_write_bio_PrivateKey(bio, pkey, cipher, passwd, len,
                                        cb, arg);

    wolfSSL_EVP_PKEY_free(pkey);

    return ret;
}

#if defined(WOLFSSL_KEY_GEN) && !defined(HAVE_USER_RSA)
/* forward declaration for wolfSSL_PEM_write_bio_RSA_PUBKEY */
static int WriteBioPUBKEY(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* key);

/* Takes an RSA public key and writes it out to a WOLFSSL_BIO
 * Returns WOLFSSL_SUCCESS or WOLFSSL_FAILURE
 */
int wolfSSL_PEM_write_bio_RSA_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa)
{
    int ret = 0;
    WOLFSSL_EVP_PKEY* pkey = NULL;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_RSA_PUBKEY");

    if (bio == NULL || rsa == NULL) {
        WOLFSSL_MSG("Bad Function Arguments");
        return WOLFSSL_FAILURE;
    }

    /* Initialize pkey structure */
    pkey = wolfSSL_EVP_PKEY_new_ex(bio->heap);
    if (pkey == NULL) {
        WOLFSSL_MSG("wolfSSL_EVP_PKEY_new_ex failed");
        return WOLFSSL_FAILURE;
    }

    pkey->type   = EVP_PKEY_RSA;
    pkey->rsa    = rsa;
    pkey->ownRsa = 0;

    ret = WriteBioPUBKEY(bio, pkey);
    wolfSSL_EVP_PKEY_free(pkey);

    return ret;
}

#ifndef NO_FILESYSTEM
int wolfSSL_PEM_write_RSAPublicKey(XFILE fp, WOLFSSL_RSA* key)
{
    int ret = WOLFSSL_SUCCESS;
    WOLFSSL_BIO* bio = NULL;

    WOLFSSL_ENTER("wolfSSL_PEM_write_RSAPublicKey");

    if (fp == XBADFILE || key == NULL) {
        WOLFSSL_MSG("Bad argument.");
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bio == NULL) {
            WOLFSSL_MSG("wolfSSL_BIO_new failed.");
            ret = WOLFSSL_FAILURE;
        }
        else if (wolfSSL_BIO_set_fp(bio, fp, BIO_NOCLOSE) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_BIO_set_fp failed.");
            ret = WOLFSSL_FAILURE;
        }
    }
    if (ret == WOLFSSL_SUCCESS && wolfSSL_PEM_write_bio_RSA_PUBKEY(bio, key)
        != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_PEM_write_bio_RSA_PUBKEY failed.");
        ret = WOLFSSL_FAILURE;
    }

    if (bio != NULL) {
        wolfSSL_BIO_free(bio);
    }

    WOLFSSL_LEAVE("wolfSSL_PEM_write_RSAPublicKey", ret);

    return ret;
}
#endif /* !NO_FILESYSTEM */
#endif /* WOLFSSL_KEY_GEN && !HAVE_USER_RSA */

/* Reads an RSA public key from a WOLFSSL_BIO into a WOLFSSL_RSA
 * Returns WOLFSSL_SUCCESS or WOLFSSL_FAILURE
 */
WOLFSSL_RSA *wolfSSL_PEM_read_bio_RSA_PUBKEY(WOLFSSL_BIO* bio,WOLFSSL_RSA** rsa,
                                             wc_pem_password_cb* cb,
                                             void *pass)
{
    WOLFSSL_EVP_PKEY* pkey;
    WOLFSSL_RSA* local;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_RSA_PUBKEY");

    pkey = wolfSSL_PEM_read_bio_PUBKEY(bio, NULL, cb, pass);
    if (pkey == NULL) {
        return NULL;
    }

    /* Since the WOLFSSL_RSA structure is being taken from WOLFSSL_EVP_PKEY the
     * flag indicating that the WOLFSSL_RSA structure is owned should be FALSE
     * to avoid having it free'd */
    pkey->ownRsa = 0;
    local = pkey->rsa;
    if (rsa != NULL) {
        *rsa = local;
    }

    wolfSSL_EVP_PKEY_free(pkey);
    return local;
}

#endif /* defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL) */
#endif /* !NO_BIO */

#if (defined(WOLFSSL_KEY_GEN) && !defined(HAVE_USER_RSA)) && \
    (defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM))

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_PEM_write_mem_RSAPrivateKey(RSA* rsa, const EVP_CIPHER* cipher,
                                        unsigned char* passwd, int passwdSz,
                                        unsigned char **pem, int *plen)
{
    byte *derBuf = NULL, *tmp, *cipherInfo = NULL;
    int  derSz = 0;
    const int type = PRIVATEKEY_TYPE;
    const char* header = NULL;
    const char* footer = NULL;

    WOLFSSL_ENTER("wolfSSL_PEM_write_mem_RSAPrivateKey");

    if (pem == NULL || plen == NULL || rsa == NULL || rsa->internal == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    if (wc_PemGetHeaderFooter(type, &header, &footer) != 0)
        return WOLFSSL_FAILURE;

    if (rsa->inSet == 0) {
        WOLFSSL_MSG("No RSA internal set, do it");

        if (SetRsaInternal(rsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetRsaInternal failed");
            return WOLFSSL_FAILURE;
        }
    }

    if ((derSz = wolfSSL_RSA_To_Der(rsa, &derBuf, 0, rsa->heap)) < 0) {
        WOLFSSL_MSG("wolfSSL_RSA_To_Der failed");
        return WOLFSSL_FAILURE;
    }

    /* encrypt DER buffer if required */
    if (passwd != NULL && passwdSz > 0 && cipher != NULL) {
        int ret;
        int blockSz = wolfSSL_EVP_CIPHER_block_size(cipher);
        byte *tmpBuf;

        /* Add space for padding */
        if (!(tmpBuf = (byte*)XREALLOC(derBuf, derSz + blockSz, rsa->heap,
                DYNAMIC_TYPE_TMP_BUFFER))) {
            WOLFSSL_MSG("Extending DER buffer failed");
            XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
            return WOLFSSL_FAILURE;
        }
        derBuf = tmpBuf;

        ret = EncryptDerKey(derBuf, &derSz, cipher,
                            passwd, passwdSz, &cipherInfo, derSz + blockSz);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("EncryptDerKey failed");
            XFREE(derBuf, rsa->heap, DYNAMIC_TYPE_DER);
            return ret;
        }

        /* tmp buffer with a max size */
        *plen = (derSz * 2) + (int)XSTRLEN(header) + 1 +
            (int)XSTRLEN(footer) + 1 + HEADER_ENCRYPTED_KEY_SIZE;
    }
    else {
        /* tmp buffer with a max size */
        *plen = (derSz * 2) + (int)XSTRLEN(header) + 1 +
            (int)XSTRLEN(footer) + 1;
    }

    tmp = (byte*)XMALLOC(*plen, NULL, DYNAMIC_TYPE_PEM);
    if (tmp == NULL) {
        WOLFSSL_MSG("malloc failed");
        XFREE(derBuf, rsa->heap, DYNAMIC_TYPE_DER);
        if (cipherInfo != NULL)
            XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);
        return WOLFSSL_FAILURE;
    }

    /* DER to PEM */
    *plen = wc_DerToPemEx(derBuf, derSz, tmp, *plen, cipherInfo, type);
    if (*plen <= 0) {
        WOLFSSL_MSG("wc_DerToPemEx failed");
        XFREE(derBuf, rsa->heap, DYNAMIC_TYPE_DER);
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        if (cipherInfo != NULL)
            XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);
        return WOLFSSL_FAILURE;
    }
    XFREE(derBuf, rsa->heap, DYNAMIC_TYPE_DER);
    if (cipherInfo != NULL)
        XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);

    *pem = (byte*)XMALLOC((*plen)+1, NULL, DYNAMIC_TYPE_KEY);
    if (*pem == NULL) {
        WOLFSSL_MSG("malloc failed");
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        return WOLFSSL_FAILURE;
    }
    XMEMSET(*pem, 0, (*plen)+1);

    if (XMEMCPY(*pem, tmp, *plen) == NULL) {
        WOLFSSL_MSG("XMEMCPY failed");
        XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        return WOLFSSL_FAILURE;
    }
    XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);

    return WOLFSSL_SUCCESS;
}


#ifndef NO_FILESYSTEM
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_PEM_write_RSAPrivateKey(XFILE fp, WOLFSSL_RSA *rsa,
                                    const EVP_CIPHER *enc,
                                    unsigned char *kstr, int klen,
                                    wc_pem_password_cb *cb, void *u)
{
    byte *pem;
    int  plen, ret;

    (void)cb;
    (void)u;

    WOLFSSL_MSG("wolfSSL_PEM_write_RSAPrivateKey");

    if (fp == XBADFILE || rsa == NULL || rsa->internal == NULL)
    {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    ret = wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, enc, kstr, klen, &pem,
        &plen);
    if (ret != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_PEM_write_mem_RSAPrivateKey failed");
        return WOLFSSL_FAILURE;
    }

    ret = (int)XFWRITE(pem, plen, 1, fp);
    if (ret != 1) {
        WOLFSSL_MSG("RSA private key file write failed");
        return WOLFSSL_FAILURE;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    return WOLFSSL_SUCCESS;
}
#endif /* NO_FILESYSTEM */
#endif /* WOLFSSL_KEY_GEN && !HAVE_USER_RSA && WOLFSSL_PEM_TO_DER */

#ifndef NO_BIO

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
/* Uses the same format of input as wolfSSL_PEM_read_bio_PrivateKey but expects
 * the results to be an RSA key.
 *
 * bio  structure to read RSA private key from
 * rsa  if not null is then set to the result
 * cb   password callback for reading PEM
 * pass password string
 *
 * returns a pointer to a new WOLFSSL_RSA structure on success and NULL on fail
 */
WOLFSSL_RSA* wolfSSL_PEM_read_bio_RSAPrivateKey(WOLFSSL_BIO* bio,
        WOLFSSL_RSA** rsa, wc_pem_password_cb* cb, void* pass)
{
    WOLFSSL_EVP_PKEY* pkey;
    WOLFSSL_RSA* local;

    WOLFSSL_ENTER("PEM_read_bio_RSAPrivateKey");

    pkey = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL, cb, pass);
    if (pkey == NULL) {
        return NULL;
    }

    /* Since the WOLFSSL_RSA structure is being taken from WOLFSSL_EVP_PKEY the
     * flag indicating that the WOLFSSL_RSA structure is owned should be FALSE
     * to avoid having it free'd */
    pkey->ownRsa = 0;
    local = pkey->rsa;
    if (rsa != NULL) {
        *rsa = local;
    }

    wolfSSL_EVP_PKEY_free(pkey);
    return local;
}
#endif /* OPENSSL_EXTRA || OPENSSL_ALL */

#endif /* NO_BIO */

#if defined(XFPRINTF) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM)
int wolfSSL_RSA_print_fp(XFILE fp, WOLFSSL_RSA* rsa, int indent)
{
    int ret = WOLFSSL_SUCCESS;
    int keySize;

    WOLFSSL_ENTER("wolfSSL_RSA_print_fp");

    if (fp == XBADFILE || rsa == NULL) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS && rsa->n != NULL) {
        keySize = wolfSSL_BN_num_bits(rsa->n);
        if (keySize == WOLFSSL_FAILURE) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            XFPRINTF(fp, "%*s", indent, "");
            XFPRINTF(fp, "RSA Private-Key: (%d bit, 2 primes)\n", keySize);
        }
    }
    if (ret == WOLFSSL_SUCCESS && rsa->n != NULL) {
        ret = PrintBNFieldFp(fp, indent, "modulus", rsa->n);
    }
    if (ret == WOLFSSL_SUCCESS && rsa->d != NULL) {
        ret = PrintBNFieldFp(fp, indent, "privateExponent", rsa->d);
    }
    if (ret == WOLFSSL_SUCCESS && rsa->p != NULL) {
        ret = PrintBNFieldFp(fp, indent, "prime1", rsa->p);
    }
    if (ret == WOLFSSL_SUCCESS && rsa->q != NULL) {
        ret = PrintBNFieldFp(fp, indent, "prime2", rsa->q);
    }
    if (ret == WOLFSSL_SUCCESS && rsa->dmp1 != NULL) {
        ret = PrintBNFieldFp(fp, indent, "exponent1", rsa->dmp1);
    }
    if (ret == WOLFSSL_SUCCESS && rsa->dmq1 != NULL) {
        ret = PrintBNFieldFp(fp, indent, "exponent2", rsa->dmq1);
    }
    if (ret == WOLFSSL_SUCCESS && rsa->iqmp != NULL) {
        ret = PrintBNFieldFp(fp, indent, "coefficient", rsa->iqmp);
    }

    WOLFSSL_LEAVE("wolfSSL_RSA_print_fp", ret);

    return ret;
}
#endif /* XFPRINTF && !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM */

#if defined(XSNPRINTF) && !defined(NO_BIO) && !defined(HAVE_FAST_RSA)
/* snprintf() must be available */

/******************************************************************************
* wolfSSL_RSA_print - writes the human readable form of RSA to bio
*
* RETURNS:
* returns WOLFSSL_SUCCESS on success, otherwise returns WOLFSSL_FAILURE
*/
int wolfSSL_RSA_print(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa, int offset)
{
    char tmp[100] = {0};
    word32 idx = 0;
    int  sz = 0;
    byte lbit = 0;
    int  rawLen = 0;
    byte* rawKey = NULL;
    RsaKey* iRsa = NULL;
    int i = 0;
    mp_int *rsaElem = NULL;
    const char *rsaStr[] = {
                          "Modulus:",
                          "PublicExponent:",
                          "PrivateExponent:",
                          "Prime1:",
                          "Prime2:",
                          "Exponent1:",
                          "Exponent2:",
                          "Coefficient:"
                        };

    WOLFSSL_ENTER("wolfSSL_RSA_print");
    (void)offset;

    if (bio == NULL || rsa == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    if ((sz = wolfSSL_RSA_size(rsa)) < 0) {
        WOLFSSL_MSG("Error getting RSA key size");
        return WOLFSSL_FAILURE;
    }
    iRsa = (RsaKey*)rsa->internal;

    XSNPRINTF(tmp, sizeof(tmp) - 1, "\n%s: (%d bit)",
            "RSA Private-Key", 8 * sz);
    tmp[sizeof(tmp) - 1] = '\0';
    if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp)) <= 0) {
        return WOLFSSL_FAILURE;
    }

    for (i=0; i<RSA_INTS; i++) {
        switch(i) {
            case 0:
                /* Print out modulus */
                rsaElem = &iRsa->n;
                break;
            case 1:
                rsaElem = &iRsa->e;
                break;
            case 2:
                rsaElem = &iRsa->d;
                break;
            case 3:
                rsaElem = &iRsa->p;
                break;
            case 4:
                rsaElem = &iRsa->q;
                break;
            case 5:
                rsaElem = &iRsa->dP;
                break;
            case 6:
                rsaElem = &iRsa->dQ;
                break;
            case 7:
                rsaElem = &iRsa->u;
                break;
            default:
                WOLFSSL_MSG("Bad index value");
        }

        if (i == 1) {
            /* Print out exponent values */
            rawLen = mp_unsigned_bin_size(rsaElem);
            if (rawLen < 0) {
                WOLFSSL_MSG("Error getting exponent size");
                return WOLFSSL_FAILURE;
            }

            if ((word32)rawLen < sizeof(word32)) {
                rawLen = sizeof(word32);
            }
            rawKey = (byte*)XMALLOC(rawLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (rawKey == NULL) {
                WOLFSSL_MSG("Memory error");
                return WOLFSSL_FAILURE;
            }
            XMEMSET(rawKey, 0, rawLen);
            if (mp_to_unsigned_bin(rsaElem, rawKey) < 0) {
                XFREE(rawKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return WOLFSSL_FAILURE;
            }
            if ((word32)rawLen <= sizeof(word32)) {
                idx = *(word32*)rawKey;
                #ifdef BIG_ENDIAN_ORDER
                    idx = ByteReverseWord32(idx);
                #endif
            }
            XSNPRINTF(tmp, sizeof(tmp) - 1, "\nExponent: %u (0x%x)", idx, idx);
            if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp)) <= 0) {
                XFREE(rawKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return WOLFSSL_FAILURE;
            }
            XFREE(rawKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        else {
            XSNPRINTF(tmp, sizeof(tmp) - 1, "\n%s\n    ", rsaStr[i]);
            tmp[sizeof(tmp) - 1] = '\0';
            if (mp_leading_bit(rsaElem)) {
                lbit = 1;
                XSTRNCAT(tmp, "00", 3);
            }

            rawLen = mp_unsigned_bin_size(rsaElem);
            rawKey = (byte*)XMALLOC(rawLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (rawKey == NULL) {
                WOLFSSL_MSG("Memory error");
                return WOLFSSL_FAILURE;
            }
            if (mp_to_unsigned_bin(rsaElem, rawKey) < 0) {
                XFREE(rawKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return WOLFSSL_FAILURE;
            }
            for (idx = 0; idx < (word32)rawLen; idx++) {
                char val[5];
                int  valSz = 5;

                if ((idx == 0) && !lbit) {
                    XSNPRINTF(val, valSz - 1, "%02x", rawKey[idx]);
                }
                else if ((idx != 0) && (((idx + lbit) % 15) == 0)) {
                    tmp[sizeof(tmp) - 1] = '\0';
                    if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp)) <= 0) {
                        XFREE(rawKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                        return WOLFSSL_FAILURE;
                    }
                    XSNPRINTF(tmp, sizeof(tmp) - 1,
                            ":\n    ");
                    XSNPRINTF(val, valSz - 1, "%02x", rawKey[idx]);
                }
                else {
                    XSNPRINTF(val, valSz - 1, ":%02x", rawKey[idx]);
                }
                XSTRNCAT(tmp, val, valSz);
            }
            XFREE(rawKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);

            /* print out remaining values */
            if ((idx > 0) && (((idx - 1 + lbit) % 15) != 0)) {
                tmp[sizeof(tmp) - 1] = '\0';
                if (wolfSSL_BIO_write(bio, tmp, (int)XSTRLEN(tmp)) <= 0) {
                    return WOLFSSL_FAILURE;
                }
            }
            lbit = 0;
        }

    }
    /* done with print out */
    if (wolfSSL_BIO_write(bio, "\n\0", (int)XSTRLEN("\n\0")) <= 0) {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* XSNPRINTF && !NO_BIO && !HAVE_FAST_RSA */

#if !defined(NO_FILESYSTEM)
#ifndef NO_WOLFSSL_STUB
WOLFSSL_RSA *wolfSSL_PEM_read_RSAPublicKey(XFILE fp, WOLFSSL_RSA **x,
                                           wc_pem_password_cb *cb, void *u)
{
    (void)fp;
    (void)x;
    (void)cb;
    (void)u;
    WOLFSSL_STUB("PEM_read_RSAPublicKey");
    WOLFSSL_MSG("wolfSSL_PEM_read_RSAPublicKey not implemented");

    return NULL;
}
#endif

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
#ifndef NO_WOLFSSL_STUB
int wolfSSL_PEM_write_RSA_PUBKEY(XFILE fp, WOLFSSL_RSA *x)
{
    (void)fp;
    (void)x;
    WOLFSSL_STUB("PEM_write_RSA_PUBKEY");
    WOLFSSL_MSG("wolfSSL_PEM_write_RSA_PUBKEY not implemented");

    return WOLFSSL_FAILURE;
}
#endif

#endif /* NO_FILESYSTEM */

WOLFSSL_RSA *wolfSSL_d2i_RSAPublicKey(WOLFSSL_RSA **r, const unsigned char **pp,
    long len)
{
    WOLFSSL_RSA *rsa = NULL;

    WOLFSSL_ENTER("d2i_RSAPublicKey");

    if (pp == NULL) {
        WOLFSSL_MSG("Bad argument");
        return NULL;
    }
    if ((rsa = wolfSSL_RSA_new()) == NULL) {
        WOLFSSL_MSG("RSA_new failed");
        return NULL;
    }

    if (wolfSSL_RSA_LoadDer_ex(rsa, *pp, (int)len, WOLFSSL_RSA_LOAD_PUBLIC)
                                                         != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("RSA_LoadDer failed");
        wolfSSL_RSA_free(rsa);
        rsa = NULL;
    }
    if (r != NULL)
        *r = rsa;

    return rsa;
}

/* Converts an RSA private key from DER format to an RSA structure.
Returns pointer to the RSA structure on success and NULL if error. */
WOLFSSL_RSA *wolfSSL_d2i_RSAPrivateKey(WOLFSSL_RSA **r,
                                       const unsigned char **derBuf, long derSz)
{
    WOLFSSL_RSA *rsa = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_RSAPrivateKey");

    /* check for bad functions arguments */
    if (derBuf == NULL) {
        WOLFSSL_MSG("Bad argument");
        return NULL;
    }
    if ((rsa = wolfSSL_RSA_new()) == NULL) {
        WOLFSSL_MSG("RSA_new failed");
        return NULL;
    }

    if (wolfSSL_RSA_LoadDer_ex(rsa, *derBuf, (int)derSz,
                                 WOLFSSL_RSA_LOAD_PRIVATE) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("RSA_LoadDer failed");
        wolfSSL_RSA_free(rsa);
        rsa = NULL;
    }
    if (r != NULL)
        *r = rsa;

    return rsa;
}

#if !defined(HAVE_FAST_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_USER_RSA)
/* Converts an internal RSA structure to DER format.
 * If "pp" is null then buffer size only is returned.
 * If "*pp" is null then a created buffer is set in *pp and the caller is
 *  responsible for free'ing it.
 * Returns size of DER on success and WOLFSSL_FAILURE if error
 */
int wolfSSL_i2d_RSAPrivateKey(WOLFSSL_RSA *rsa, unsigned char **pp)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_i2d_RSAPrivateKey");

    /* check for bad functions arguments */
    if (rsa == NULL) {
        WOLFSSL_MSG("Bad Function Arguments");
        return BAD_FUNC_ARG;
    }

    /* No heap hint as this gets returned to the user */
    if ((ret = wolfSSL_RSA_To_Der(rsa, pp, 0, NULL)) < 0) {
        WOLFSSL_MSG("wolfSSL_RSA_To_Der failed");
        return WOLFSSL_FAILURE;
    }

    return ret; /* returns size of DER if successful */
}


int wolfSSL_i2d_RSAPublicKey(WOLFSSL_RSA *rsa, unsigned char **pp)
{
    int ret;

    /* check for bad functions arguments */
    if (rsa == NULL) {
        WOLFSSL_MSG("Bad Function Arguments");
        return BAD_FUNC_ARG;
    }

    /* No heap hint as this gets returned to the user */
    if ((ret = wolfSSL_RSA_To_Der(rsa, (byte**)pp, 1, NULL)) < 0) {
        WOLFSSL_MSG("wolfSSL_RSA_To_Der failed");
        return WOLFSSL_FAILURE;
    }

    return ret;
}
#endif /* !defined(HAVE_FAST_RSA) && defined(WOLFSSL_KEY_GEN) &&
        * !defined(HAVE_USER_RSA) */

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* return WOLFSSL_SUCCESS if success, WOLFSSL_FATAL_ERROR if error */
int wolfSSL_RSA_LoadDer(WOLFSSL_RSA* rsa, const unsigned char* derBuf,
    int derSz)
{
  return wolfSSL_RSA_LoadDer_ex(rsa, derBuf, derSz, WOLFSSL_RSA_LOAD_PRIVATE);
}


int wolfSSL_RSA_LoadDer_ex(WOLFSSL_RSA* rsa, const unsigned char* derBuf,
                                                     int derSz, int opt)
{
    int ret;
    word32 idx = 0;
    word32 algId;

    WOLFSSL_ENTER("wolfSSL_RSA_LoadDer");

    if (rsa == NULL || rsa->internal == NULL || derBuf == NULL || derSz <= 0) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    rsa->pkcs8HeaderSz = 0;
    /* Check if input buffer has PKCS8 header. In the case that it does not
     * have a PKCS8 header then do not error out. */
    if ((ret = ToTraditionalInline_ex((const byte*)derBuf, &idx, (word32)derSz,
                                                                 &algId)) > 0) {
        WOLFSSL_MSG("Found PKCS8 header");
        rsa->pkcs8HeaderSz = (word16)idx;
    }
    else {
        if (ret != ASN_PARSE_E) {
            WOLFSSL_MSG("Unexpected error with trying to remove PKCS8 header");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    if (opt == WOLFSSL_RSA_LOAD_PRIVATE) {
        ret = wc_RsaPrivateKeyDecode(derBuf, &idx, (RsaKey*)rsa->internal,
            derSz);
    }
    else {
        ret = wc_RsaPublicKeyDecode(derBuf, &idx, (RsaKey*)rsa->internal,
            derSz);
    }

    if (ret < 0) {
        if (opt == WOLFSSL_RSA_LOAD_PRIVATE) {
             WOLFSSL_MSG("RsaPrivateKeyDecode failed");
        }
        else {
             WOLFSSL_MSG("RsaPublicKeyDecode failed");
        }
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetRsaExternal(rsa) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetRsaExternal failed");
        return WOLFSSL_FATAL_ERROR;
    }

    rsa->inSet = 1;

    return WOLFSSL_SUCCESS;
}

#if defined(WC_RSA_PSS) && (defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || \
        defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX))
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
/*
 *                                +-----------+
 *                                |     M     |
 *                                +-----------+
 *                                      |
 *                                      V
 *                                    Hash
 *                                      |
 *                                      V
 *                        +--------+----------+----------+
 *                   M' = |Padding1|  mHash   |   salt   |
 *                        +--------+----------+----------+
 *                                       |
 *             +--------+----------+     V
 *       DB =  |Padding2|maskedseed|   Hash
 *             +--------+----------+     |
 *                       |               |
 *                       V               |    +--+
 *                      xor <--- MGF <---|    |bc|
 *                       |               |    +--+
 *                       |               |      |
 *                       V               V      V
 *             +-------------------+----------+--+
 *       EM =  |    maskedDB       |maskedseed|bc|
 *             +-------------------+----------+--+
 * Diagram taken from https://tools.ietf.org/html/rfc3447#section-9.1
 */
int wolfSSL_RSA_padding_add_PKCS1_PSS(WOLFSSL_RSA *rsa, unsigned char *EM,
    const unsigned char *mHash, const WOLFSSL_EVP_MD *hashAlg, int saltLen)
{
    int hashLen, emLen, mgf;
    int ret = WOLFSSL_FAILURE;
    int initTmpRng = 0;
    WC_RNG *rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRNG = NULL;
#else
    WC_RNG  _tmpRNG[1];
    WC_RNG* tmpRNG = _tmpRNG;
#endif
    enum wc_HashType hashType;

    WOLFSSL_ENTER("wolfSSL_RSA_padding_add_PKCS1_PSS");

    if (!rsa || !EM || !mHash || !hashAlg) {
        return WOLFSSL_FAILURE;
    }

    if (!(rng = WOLFSSL_RSA_GetRNG(rsa, (WC_RNG**)&tmpRNG, &initTmpRng))) {
        WOLFSSL_MSG("WOLFSSL_RSA_GetRNG error");
        goto cleanup;
    }

    if (!rsa->exSet && SetRsaExternal(rsa) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetRsaExternal error");
        goto cleanup;
    }

    hashType = EvpMd2MacType(hashAlg);
    if (hashType > WC_HASH_TYPE_MAX) {
        WOLFSSL_MSG("EvpMd2MacType error");
        goto cleanup;
    }

   if ((mgf = wc_hash2mgf(hashType)) == WC_MGF1NONE) {
       WOLFSSL_MSG("wc_hash2mgf error");
       goto cleanup;
   }

    if ((hashLen = wolfSSL_EVP_MD_size(hashAlg)) < 0) {
        WOLFSSL_MSG("wolfSSL_EVP_MD_size error");
        goto cleanup;
    }

    if ((emLen = wolfSSL_RSA_size(rsa)) <= 0) {
        WOLFSSL_MSG("wolfSSL_RSA_size error");
        goto cleanup;
    }

    switch (saltLen) {
        /* Negative saltLen values are treated differently */
        case RSA_PSS_SALTLEN_DIGEST:
            saltLen = hashLen;
            break;
        case RSA_PSS_SALTLEN_MAX_SIGN:
        case RSA_PSS_SALTLEN_MAX:
            saltLen = emLen - hashLen - 2;
            break;
        default:
            if (saltLen < 0) {
                /* Not any currently implemented negative value */
                WOLFSSL_MSG("invalid saltLen");
                goto cleanup;
            }
    }

    if (wc_RsaPad_ex(mHash, hashLen, EM, emLen,
                     RSA_BLOCK_TYPE_1, rng, WC_RSA_PSS_PAD,
                     hashType, mgf, NULL, 0, saltLen,
                     wolfSSL_BN_num_bits(rsa->n), NULL) != MP_OKAY) {
        WOLFSSL_MSG("wc_RsaPad_ex error");
        goto cleanup;
    }

    ret = WOLFSSL_SUCCESS;
cleanup:
    if (initTmpRng)
        wc_FreeRng(tmpRNG);
#ifdef WOLFSSL_SMALL_STACK
    if (tmpRNG)
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

/*
 * Refer to wolfSSL_RSA_padding_add_PKCS1_PSS
 * for an explanation of the parameters.
 */
int wolfSSL_RSA_verify_PKCS1_PSS(WOLFSSL_RSA *rsa, const unsigned char *mHash,
                                 const WOLFSSL_EVP_MD *hashAlg,
                                 const unsigned char *EM, int saltLen)
{
    int hashLen, mgf, emLen, mPrimeLen;
    enum wc_HashType hashType;
    byte *mPrime = NULL;
    byte *buf = NULL;

    WOLFSSL_ENTER("wolfSSL_RSA_verify_PKCS1_PSS");

    if (!rsa || !mHash || !hashAlg || !EM) {
        return WOLFSSL_FAILURE;
    }

    if ((hashLen = wolfSSL_EVP_MD_size(hashAlg)) < 0) {
        return WOLFSSL_FAILURE;
    }

    if ((emLen = wolfSSL_RSA_size(rsa)) <= 0) {
        WOLFSSL_MSG("wolfSSL_RSA_size error");
        return WOLFSSL_FAILURE;
    }

    switch (saltLen) {
    /* Negative saltLen values are treated differently */
        case RSA_PSS_SALTLEN_DIGEST:
            saltLen = hashLen;
            break;
        case RSA_PSS_SALTLEN_MAX_SIGN:
        case RSA_PSS_SALTLEN_MAX:
            saltLen = emLen - hashLen - 2;
            break;
        default:
            if (saltLen < 0) {
                /* Not any currently implemented negative value */
                WOLFSSL_MSG("invalid saltLen");
                return WOLFSSL_FAILURE;
            }
    }

    if (!rsa->exSet && SetRsaExternal(rsa) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    hashType = EvpMd2MacType(hashAlg);
    if (hashType > WC_HASH_TYPE_MAX) {
        WOLFSSL_MSG("EvpMd2MacType error");
        return WOLFSSL_FAILURE;
    }

    if ((mgf = wc_hash2mgf(hashType)) == WC_MGF1NONE) {
        WOLFSSL_MSG("wc_hash2mgf error");
        return WOLFSSL_FAILURE;
    }

    if ((hashLen = wolfSSL_EVP_MD_size(hashAlg)) < 0) {
        WOLFSSL_MSG("wolfSSL_EVP_MD_size error");
        return WOLFSSL_FAILURE;
    }

    if (!(buf = (byte*)XMALLOC(emLen, NULL, DYNAMIC_TYPE_TMP_BUFFER))) {
        WOLFSSL_MSG("malloc error");
        return WOLFSSL_FAILURE;
    }
    XMEMCPY(buf, EM, emLen);

    /* Remove and verify the PSS padding */
    if ((mPrimeLen = wc_RsaUnPad_ex(buf, emLen, &mPrime,
                                    RSA_BLOCK_TYPE_1, WC_RSA_PSS_PAD, hashType,
                                    mgf, NULL, 0, saltLen,
                                    wolfSSL_BN_num_bits(rsa->n), NULL)) < 0) {
        WOLFSSL_MSG("wc_RsaPad_ex error");
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }

    /* Verify the hash is correct */
    if (wc_RsaPSS_CheckPadding_ex(mHash, hashLen, mPrime, mPrimeLen, hashType,
                                  saltLen, wolfSSL_BN_num_bits(rsa->n))
                                  != MP_OKAY) {
        WOLFSSL_MSG("wc_RsaPSS_CheckPadding_ex error");
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return WOLFSSL_SUCCESS;
}
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* WC_RSA_PSS && (OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY
        *                || WOLFSSL_NGINX)
        */

#if defined(OPENSSL_EXTRA)
WOLFSSL_RSA_METHOD *wolfSSL_RSA_meth_new(const char *name, int flags)
{
    int name_len;
    WOLFSSL_RSA_METHOD* meth;

    if (name == NULL) {
        return NULL;
    }

    meth = (WOLFSSL_RSA_METHOD*)XMALLOC(sizeof(WOLFSSL_RSA_METHOD), NULL,
        DYNAMIC_TYPE_OPENSSL);
    name_len = (int)XSTRLEN(name);
    if (!meth) {
        return NULL;
    }
    meth->flags = flags;
    meth->name = (char*)XMALLOC(name_len+1, NULL, DYNAMIC_TYPE_OPENSSL);
    if (!meth->name) {
        XFREE(meth, NULL, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }
    XMEMCPY(meth->name, name, name_len+1);

    return meth;
}

void wolfSSL_RSA_meth_free(WOLFSSL_RSA_METHOD *meth)
{
    if (meth) {
        XFREE(meth->name, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(meth, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

#ifndef NO_WOLFSSL_STUB
int wolfSSL_RSA_meth_set(WOLFSSL_RSA_METHOD *rsa, void* p)
{
    (void)rsa;
    (void)p;
    WOLFSSL_STUB("RSA_METHOD is not implemented.");
    return 1;
}
#endif

int wolfSSL_RSA_set_method(WOLFSSL_RSA *rsa, WOLFSSL_RSA_METHOD *meth)
{
    if (rsa)
        rsa->meth = meth;
    return 1;
}

const WOLFSSL_RSA_METHOD* wolfSSL_RSA_get_method(const WOLFSSL_RSA *rsa)
{
    if (!rsa) {
        return NULL;
    }
    return rsa->meth;
}

const WOLFSSL_RSA_METHOD* wolfSSL_RSA_get_default_method(void)
{
    return wolfSSL_RSA_meth_new("wolfSSL RSA", 0);
}

int wolfSSL_RSA_flags(const WOLFSSL_RSA *r)
{
    if (r && r->meth) {
        return r->meth->flags;
    } else {
        return 0;
    }
}

void wolfSSL_RSA_set_flags(WOLFSSL_RSA *r, int flags)
{
    if (r && r->meth) {
        r->meth->flags |= flags;
    }
}

void wolfSSL_RSA_clear_flags(WOLFSSL_RSA *r, int flags)
{
    if (r && r->meth) {
        r->meth->flags &= ~flags;
    }
}

int wolfSSL_RSA_test_flags(const WOLFSSL_RSA *r, int flags)
{
    return r && r->meth ? r->meth->flags & flags : 0;
}

#if defined(WOLFSSL_KEY_GEN) && !defined(HAVE_USER_RSA)
WOLFSSL_RSA* wolfSSL_RSAPublicKey_dup(WOLFSSL_RSA *rsa)
{
    int derSz = 0;
    byte *derBuf = NULL;
    WOLFSSL_RSA* local;

    WOLFSSL_ENTER("wolfSSL_RSAPublicKey_dup");

    if (!rsa) {
        return NULL;
    }

    local = wolfSSL_RSA_new();
    if (local == NULL) {
        WOLFSSL_MSG("Error creating a new WOLFSSL_RSA structure");
        return NULL;
    }

    if ((derSz = wolfSSL_RSA_To_Der(rsa, &derBuf, 1, rsa->heap)) < 0) {
        WOLFSSL_MSG("wolfSSL_RSA_To_Der failed");
        return NULL;
    }

    if (wolfSSL_RSA_LoadDer_ex(local,
                derBuf, derSz,
                WOLFSSL_RSA_LOAD_PUBLIC) != WOLFSSL_SUCCESS) {
        wolfSSL_RSA_free(local);
        local = NULL;
    }
    XFREE(derBuf, rsa->heap, DYNAMIC_TYPE_ASN1);
    return local;
}
#endif

void* wolfSSL_RSA_get_ex_data(const WOLFSSL_RSA *rsa, int idx)
{
    WOLFSSL_ENTER("wolfSSL_RSA_get_ex_data");
#ifdef HAVE_EX_DATA
    if (rsa) {
        return wolfSSL_CRYPTO_get_ex_data(&rsa->ex_data, idx);
    }
#else
    (void)rsa;
    (void)idx;
#endif
    return NULL;
}

int wolfSSL_RSA_set_ex_data(WOLFSSL_RSA *rsa, int idx, void *data)
{
    WOLFSSL_ENTER("wolfSSL_RSA_set_ex_data");
    #ifdef HAVE_EX_DATA
    if (rsa) {
        return wolfSSL_CRYPTO_set_ex_data(&rsa->ex_data, idx, data);
    }
    #else
    (void)rsa;
    (void)idx;
    (void)data;
    #endif
    return WOLFSSL_FAILURE;
}

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
int wolfSSL_RSA_set_ex_data_with_cleanup(
    WOLFSSL_RSA *rsa,
    int idx,
    void *data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine)
{
    WOLFSSL_ENTER("wolfSSL_RSA_set_ex_data_with_cleanup");
    if (rsa) {
        return wolfSSL_CRYPTO_set_ex_data_with_cleanup(&rsa->ex_data, idx, data,
                                                       cleanup_routine);
    }
    return WOLFSSL_FAILURE;
}
#endif /* HAVE_EX_DATA_CLEANUP_HOOKS */

int wolfSSL_RSA_set0_key(WOLFSSL_RSA *r, WOLFSSL_BIGNUM *n, WOLFSSL_BIGNUM *e,
                         WOLFSSL_BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((!r->n && !n) || (!r->e && !e))
        return 0;

    if (n) {
        wolfSSL_BN_free(r->n);
        r->n = n;
    }
    if (e) {
        wolfSSL_BN_free(r->e);
        r->e = e;
    }
    if (d) {
        wolfSSL_BN_clear_free(r->d);
        r->d = d;
    }

    return SetRsaInternal(r) == WOLFSSL_SUCCESS ?
            WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}
#endif /* OPENSSL_EXTRA */

/* increments ref count of WOLFSSL_RSA. Return 1 on success, 0 on error */
int wolfSSL_RSA_up_ref(WOLFSSL_RSA* rsa)
{
    if (rsa) {
#ifndef SINGLE_THREADED
        if (wc_LockMutex(&rsa->refMutex) != 0) {
            WOLFSSL_MSG("Failed to lock x509 mutex");
            return WOLFSSL_FAILURE;
        }
#endif
        rsa->refCount++;
#ifndef SINGLE_THREADED
        wc_UnLockMutex(&rsa->refMutex);
#endif

        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}

#endif /* OPENSSL_EXTRA_X509_SMALL || OPENSSL_EXTRA */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX) || defined(WOLFSSL_QT)

#ifndef NO_BIO

#if !defined(HAVE_FAST_RSA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(HAVE_USER_RSA)
/* Converts an rsa key from a bio buffer into an internal rsa structure.
Returns a pointer to the new WOLFSSL_RSA structure. */
WOLFSSL_RSA* wolfSSL_d2i_RSAPrivateKey_bio(WOLFSSL_BIO *bio, WOLFSSL_RSA **out)
{
    const unsigned char* bioMem = NULL;
    int bioMemSz = 0;
    WOLFSSL_RSA* key = NULL;
    unsigned char *maxKeyBuf = NULL;
    unsigned char* bufPtr = NULL;
    unsigned char* extraBioMem = NULL;
    int extraBioMemSz = 0;
    int derLength = 0;
    int j = 0, i = 0;

    WOLFSSL_ENTER("wolfSSL_d2i_RSAPrivateKey_bio()");

    if (bio == NULL) {
        WOLFSSL_MSG("Bad Function Argument");
        return NULL;
    }
    (void)out;

    bioMemSz = wolfSSL_BIO_get_len(bio);
    if (bioMemSz <= 0) {
        WOLFSSL_MSG("wolfSSL_BIO_get_len() failure");
        return NULL;
    }

    bioMem = (unsigned char*)XMALLOC(bioMemSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (bioMem == NULL) {
        WOLFSSL_MSG("Malloc failure");
        return NULL;
    }

    maxKeyBuf = (unsigned char*)XMALLOC(4096, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (maxKeyBuf == NULL) {
        WOLFSSL_MSG("Malloc failure");
        XFREE((unsigned char*)bioMem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    bufPtr = maxKeyBuf;
    if (wolfSSL_BIO_read(bio, (unsigned char*)bioMem, (int)bioMemSz) == bioMemSz) {
        const byte* bioMemPt = bioMem; /* leave bioMem pointer unaltered */
        if ((key = wolfSSL_d2i_RSAPrivateKey(NULL, &bioMemPt, bioMemSz)) == NULL) {
            XFREE((unsigned char*)bioMem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE((unsigned char*)maxKeyBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return NULL;
        }

        /* This function is used to get the total length of the rsa key. */
        derLength = wolfSSL_i2d_RSAPrivateKey(key, &bufPtr);

        /* Write extra data back into bio object if necessary. */
        extraBioMemSz = (bioMemSz - derLength);
        if (extraBioMemSz > 0) {
            extraBioMem = (unsigned char *)XMALLOC(extraBioMemSz, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (extraBioMem == NULL) {
                WOLFSSL_MSG("Malloc failure");
                XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE((unsigned char*)bioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE((unsigned char*)maxKeyBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
                return NULL;
            }

            for (i = derLength; i < bioMemSz; i++) {
                *(extraBioMem + j) = *(bioMem + i);
                j++;
            }

            wolfSSL_BIO_write(bio, extraBioMem, extraBioMemSz);
            if (wolfSSL_BIO_get_len(bio) <= 0) {
                WOLFSSL_MSG("Failed to write memory to bio");
                XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE((unsigned char*)bioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
                XFREE((unsigned char*)maxKeyBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
                return NULL;
            }
            XFREE((unsigned char*)extraBioMem, bio->heap,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        }

        if (out != NULL && key != NULL) {
            *out = key;
        }
    }
    XFREE((unsigned char*)bioMem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE((unsigned char*)maxKeyBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return key;
}
#endif /* !HAVE_FAST_RSA && WOLFSSL_KEY_GEN && !HAVE_USER_RSA */

#endif /* !NO_BIO */

#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_QT */

#ifdef OPENSSL_EXTRA

#if !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA)
/* Openssl -> WolfSSL */
int SetRsaInternal(WOLFSSL_RSA* rsa)
{
    RsaKey* key;
    WOLFSSL_MSG("Entering SetRsaInternal");

    if (rsa == NULL || rsa->internal == NULL) {
        WOLFSSL_MSG("rsa key NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    key = (RsaKey*)rsa->internal;

    if (rsa->n != NULL) {
        if (SetIndividualInternal(rsa->n, &key->n) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("rsa n key error");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    if (rsa->e != NULL) {
        if (SetIndividualInternal(rsa->e, &key->e) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("rsa e key error");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    /* public key */
    key->type = RSA_PUBLIC;

    if (rsa->d != NULL) {
        if (SetIndividualInternal(rsa->d, &key->d) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("rsa d key error");
            return WOLFSSL_FATAL_ERROR;
        }

        /* private key */
        key->type = RSA_PRIVATE;
    }

    if (rsa->p != NULL &&
        SetIndividualInternal(rsa->p, &key->p) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa p key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (rsa->q != NULL &&
        SetIndividualInternal(rsa->q, &key->q) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa q key error");
        return WOLFSSL_FATAL_ERROR;
    }

#ifndef RSA_LOW_MEM
    if (rsa->dmp1 != NULL &&
        SetIndividualInternal(rsa->dmp1, &key->dP) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa dP key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (rsa->dmq1 != NULL &&
        SetIndividualInternal(rsa->dmq1, &key->dQ) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa dQ key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (rsa->iqmp != NULL &&
        SetIndividualInternal(rsa->iqmp, &key->u) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa u key error");
        return WOLFSSL_FATAL_ERROR;
    }
#endif /* !RSA_LOW_MEM */

    rsa->inSet = 1;

    return WOLFSSL_SUCCESS;
}

/* WOLFSSL_SUCCESS on ok */
#ifndef NO_WOLFSSL_STUB
int wolfSSL_RSA_blinding_on(WOLFSSL_RSA* rsa, WOLFSSL_BN_CTX* bn)
{
    (void)rsa;
    (void)bn;
    WOLFSSL_STUB("RSA_blinding_on");
    WOLFSSL_MSG("wolfSSL_RSA_blinding_on");

    return WOLFSSL_SUCCESS;  /* on by default */
}
#endif

/* If not using old FIPS or CAVP selftest or not using fast or user RSA, able
 * to check RSA key. */
#if !defined(WOLFSSL_RSA_PUBLIC_ONLY) && !defined(HAVE_FAST_RSA) && \
    !defined(HAVE_USER_RSA) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))) && \
    !defined(HAVE_SELFTEST) && !defined(HAVE_INTEL_QA) && \
    defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_NO_RSA_KEY_CHECK)
int wolfSSL_RSA_check_key(const WOLFSSL_RSA* rsa)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_RSA_check_key");

    if (rsa == NULL || rsa->internal == NULL) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS && wc_CheckRsaKey((RsaKey*)rsa->internal) != 0) {
        ret = WOLFSSL_FAILURE;
    }

    WOLFSSL_LEAVE("wolfSSL_RSA_check_key", ret);

    return ret;
}
#endif

/* return compliant with OpenSSL
 *   size of encrypted data if success , -1 if error
 */
int wolfSSL_RSA_public_encrypt(int len, const unsigned char* fr,
                            unsigned char* to, WOLFSSL_RSA* rsa, int padding)
{
    int initTmpRng = 0;
    WC_RNG *rng = NULL;
    int outLen;
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRNG = NULL;
#else
    WC_RNG  _tmpRNG[1];
    WC_RNG* tmpRNG = _tmpRNG;
#endif
#if !defined(HAVE_FIPS) && !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA)
    int  mgf = WC_MGF1NONE;
    enum wc_HashType hash = WC_HASH_TYPE_NONE;
    int pad_type;
#endif

    WOLFSSL_ENTER("RSA_public_encrypt");

#if !defined(HAVE_FIPS) && !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA)
    switch (padding) {
    case RSA_PKCS1_PADDING:
        pad_type = WC_RSA_PKCSV15_PAD;
        break;
    case RSA_PKCS1_OAEP_PADDING:
        pad_type = WC_RSA_OAEP_PAD;
        hash = WC_HASH_TYPE_SHA;
        mgf = WC_MGF1SHA1;
        break;
    case RSA_PKCS1_PSS_PADDING:
        pad_type = WC_RSA_PSS_PAD;
        hash = WC_HASH_TYPE_SHA256;
       mgf  = WC_MGF1SHA256;
        break;
    case RSA_NO_PADDING:
        pad_type = WC_RSA_NO_PAD;
        break;
    default:
        WOLFSSL_MSG("RSA_public_encrypt unsupported padding");
        return WOLFSSL_FAILURE;
    }
#endif

    if (rsa->inSet == 0) {
        if (SetRsaInternal(rsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetRsaInternal failed");
            return WOLFSSL_FAILURE;
        }
    }

    outLen = wolfSSL_RSA_size(rsa);
    if (outLen == 0) {
        WOLFSSL_MSG("Bad RSA size");
    }

    rng = WOLFSSL_RSA_GetRNG(rsa, (WC_RNG**)&tmpRNG, &initTmpRng);
    if (rng) {
#if !defined(HAVE_FIPS) && !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA)
        ret = wc_RsaPublicEncrypt_ex(fr, len, to, outLen,
                             (RsaKey*)rsa->internal, rng, pad_type,
                             hash, mgf, NULL, 0);
#else
        if (padding == RSA_PKCS1_PADDING) {
            ret = wc_RsaPublicEncrypt(fr, len, to, outLen,
                                (RsaKey*)rsa->internal, rng);
        }
        else {
            WOLFSSL_MSG("RSA_public_encrypt pad type not supported in FIPS");
            ret = WOLFSSL_FAILURE;
        }
#endif
    }

    if (initTmpRng)
        wc_FreeRng(tmpRNG);
#ifdef WOLFSSL_SMALL_STACK
    if (tmpRNG)
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    WOLFSSL_LEAVE("RSA_public_encrypt", ret);

    if (ret <= 0) {
        ret = WOLFSSL_FAILURE;
    }
    return ret;
}



/* return compliant with OpenSSL
 *   size of plain recovered data if success , -1 if error
 */
int wolfSSL_RSA_private_decrypt(int len, const unsigned char* fr,
                            unsigned char* to, WOLFSSL_RSA* rsa, int padding)
{
    int outLen;
    int ret = 0;
  #if !defined(HAVE_FIPS) && !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA)
    int mgf = WC_MGF1NONE;
    enum wc_HashType hash = WC_HASH_TYPE_NONE;
    int pad_type;
  #endif

    WOLFSSL_ENTER("RSA_private_decrypt");

#if !defined(HAVE_FIPS) && !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA)
    switch (padding) {
    case RSA_PKCS1_PADDING:
        pad_type = WC_RSA_PKCSV15_PAD;
        break;
    case RSA_PKCS1_OAEP_PADDING:
        pad_type = WC_RSA_OAEP_PAD;
        hash = WC_HASH_TYPE_SHA;
        mgf = WC_MGF1SHA1;
        break;
    case RSA_PKCS1_PSS_PADDING:
        pad_type = WC_RSA_PSS_PAD;
        hash = WC_HASH_TYPE_SHA256;
        mgf  = WC_MGF1SHA256;
        break;
    case RSA_NO_PADDING:
        pad_type = WC_RSA_NO_PAD;
        break;
    default:
        WOLFSSL_MSG("RSA_private_decrypt unsupported padding");
        return WOLFSSL_FAILURE;
    }
#endif

    if (rsa->inSet == 0) {
        if (SetRsaInternal(rsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetRsaInternal failed");
            return WOLFSSL_FAILURE;
        }
    }

    outLen = wolfSSL_RSA_size(rsa);
    if (outLen == 0) {
        WOLFSSL_MSG("Bad RSA size");
    }

    /* size of 'to' buffer must be size of RSA key */
#if !defined(HAVE_FIPS) && !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA)
    ret = wc_RsaPrivateDecrypt_ex(fr, len, to, outLen,
                            (RsaKey*)rsa->internal, pad_type,
                            hash, mgf, NULL, 0);
#else
    if (padding == RSA_PKCS1_PADDING) {
        ret = wc_RsaPrivateDecrypt(fr, len, to, outLen,
                                (RsaKey*)rsa->internal);
    }
    else {
        WOLFSSL_MSG("RSA_private_decrypt pad type not supported in FIPS");
        ret = WOLFSSL_FAILURE;
    }
#endif

    if (ret <= 0) {
        ret = WOLFSSL_FAILURE;
    }
    WOLFSSL_LEAVE("RSA_private_decrypt", ret);

    return ret;
}

int wolfSSL_RSA_public_decrypt(int flen, const unsigned char* from,
                          unsigned char* to, WOLFSSL_RSA* rsa, int padding)
{
    int ret = 0;
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2))
    int pad_type;
#endif

    WOLFSSL_ENTER("RSA_public_decrypt");

    if (rsa == NULL || rsa->internal == NULL || from == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2))
    switch (padding) {
    case RSA_PKCS1_PADDING:
        pad_type = WC_RSA_PKCSV15_PAD;
        break;
    case RSA_PKCS1_OAEP_PADDING:
        pad_type = WC_RSA_OAEP_PAD;
        break;
    case RSA_PKCS1_PSS_PADDING:
        pad_type = WC_RSA_PSS_PAD;
        break;
    case RSA_NO_PADDING:
        pad_type = WC_RSA_NO_PAD;
        break;
    default:
        WOLFSSL_MSG("RSA_public_decrypt unsupported padding");
        return WOLFSSL_FATAL_ERROR;
    }
#endif

    if (rsa->inSet == 0) {
        WOLFSSL_MSG("No RSA internal set, do it");

        if (SetRsaInternal(rsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetRsaInternal failed");
            return WOLFSSL_FATAL_ERROR;
        }
    }

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2))
    /* size of 'to' buffer must be size of RSA key */
    ret = wc_RsaSSL_Verify_ex(from, flen, to, wolfSSL_RSA_size(rsa),
                               (RsaKey*)rsa->internal, pad_type);
#else
    /* For FIPS v1/v2 only PKCSV15 padding is supported */
    if (padding == RSA_PKCS1_PADDING) {
        ret = wc_RsaSSL_Verify(from, flen, to, wolfSSL_RSA_size(rsa),
            (RsaKey*)rsa->internal);
    }
    else {
        WOLFSSL_MSG("RSA_public_decrypt pad type not supported in FIPS");
        ret = WOLFSSL_FATAL_ERROR;
    }
#endif

    WOLFSSL_LEAVE("RSA_public_decrypt", ret);

    if (ret <= 0) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    return ret;
}

/* RSA private encrypt calls wc_RsaSSL_Sign. Similar function set up as RSA
 * public decrypt.
 *
 * len  Length of input buffer
 * in   Input buffer to sign
 * out  Output buffer (expected to be greater than or equal to RSA key size)
 * rsa     Key to use for encryption
 * padding Type of RSA padding to use.
 */
int wolfSSL_RSA_private_encrypt(int len, const unsigned char* in,
                            unsigned char* out, WOLFSSL_RSA* rsa, int padding)
{
    int sz = 0;
    WC_RNG* rng = NULL;
#if !defined(WC_RSA_BLINDING) || defined(HAVE_USER_RSA)
    WC_RNG rng_lcl;
#endif
    RsaKey* key;

    WOLFSSL_MSG("wolfSSL_RSA_private_encrypt");

    if (len < 0 || rsa == NULL || rsa->internal == NULL || in == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return 0;
    }

    if (
    #ifdef WC_RSA_PSS
        padding != RSA_PKCS1_PSS_PADDING &&
    #endif
    #ifdef WC_RSA_NO_PADDING
        padding != RSA_NO_PADDING &&
    #endif
        padding != RSA_PKCS1_PADDING) {
        WOLFSSL_MSG("wolfSSL_RSA_private_encrypt unsupported padding");
        return 0;
    }

    if (rsa->inSet == 0)
    {
        WOLFSSL_MSG("Setting internal RSA structure");

        if (SetRsaInternal(rsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetRsaInternal failed");
            return 0;
        }
    }

    key = (RsaKey*)rsa->internal;
#if defined(WC_RSA_BLINDING) && !defined(HAVE_USER_RSA)
    rng = key->rng;
#else
    rng = &rng_lcl;
    #ifndef HAVE_FIPS
    if (wc_InitRng_ex(rng, key->heap, INVALID_DEVID) != 0)
    #else
    if (wc_InitRng(rng) != 0)
    #endif
    {
        WOLFSSL_MSG("Error with random number");
        return WOLFSSL_FATAL_ERROR;
    }
#endif

    /* size of output buffer must be size of RSA key */
    switch (padding) {
        case RSA_PKCS1_PADDING:
            sz = wc_RsaSSL_Sign(in, (word32)len, out, wolfSSL_RSA_size(rsa),
                    key, rng);
            break;
    #ifdef WC_RSA_PSS
        case RSA_PKCS1_PSS_PADDING:
            sz = wc_RsaPSS_Sign(in, (word32)len, out, wolfSSL_RSA_size(rsa),
                    WC_HASH_TYPE_NONE, WC_MGF1NONE, key, rng);
            break;
    #endif
    #ifdef WC_RSA_NO_PADDING
        case RSA_NO_PADDING:
        {
            word32 outLen = (word32)len;
            sz = wc_RsaFunction(in, (word32)len, out, &outLen,
                    RSA_PRIVATE_ENCRYPT, key, rng);
            if (sz == 0)
                sz = (int)outLen;
            break;
        }
    #endif
        default:
            sz = BAD_FUNC_ARG;
            break;
    }

    #if !defined(WC_RSA_BLINDING) || defined(HAVE_USER_RSA)
    if (wc_FreeRng(rng) != 0) {
        WOLFSSL_MSG("Error freeing random number generator");
        return WOLFSSL_FATAL_ERROR;
    }
    #endif
    if (sz <= 0) {
        WOLFSSL_LEAVE("wolfSSL_RSA_private_encrypt", sz);
        return 0;
    }

    return sz;
}
#endif /* HAVE_USER_RSA */

/* return compliant with OpenSSL
 *   RSA modulus size in bytes, -1 if error
 */
int wolfSSL_RSA_size(const WOLFSSL_RSA* rsa)
{
    WOLFSSL_ENTER("wolfSSL_RSA_size");

    if (rsa == NULL)
        return WOLFSSL_FATAL_ERROR;
    if (rsa->inSet == 0)
    {
        if (SetRsaInternal((WOLFSSL_RSA*)rsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetRsaInternal failed");
            return 0;
        }
    }
    return wc_RsaEncryptSize((RsaKey*)rsa->internal);
}
/* return RSA modulus in bits                      */
/* @param rsa a pointer to WOLFSSL_RSA structure   */
/* @return RSA modulus size in bits, 0 if error    */
int wolfSSL_RSA_bits(const WOLFSSL_RSA* rsa)
{
    WOLFSSL_ENTER("wolfSSL_RSA_bits");

    if (rsa == NULL)
        return WOLFSSL_FAILURE;

    return wolfSSL_BN_num_bits(rsa->n);
}
#endif /* OPENSSL_EXTRA */

#if !defined(HAVE_USER_RSA) && !defined(HAVE_FAST_RSA) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
/* WolfSSL -> OpenSSL */
int SetRsaExternal(WOLFSSL_RSA* rsa)
{
    RsaKey* key;
    WOLFSSL_MSG("Entering SetRsaExternal");

    if (rsa == NULL || rsa->internal == NULL) {
        WOLFSSL_MSG("rsa key NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    key = (RsaKey*)rsa->internal;

    if (SetIndividualExternal(&rsa->n, &key->n) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa n key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&rsa->e, &key->e) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa e key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (key->type == RSA_PRIVATE) {
        if (SetIndividualExternal(&rsa->d, &key->d) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("rsa d key error");
            return WOLFSSL_FATAL_ERROR;
        }

        if (SetIndividualExternal(&rsa->p, &key->p) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("rsa p key error");
            return WOLFSSL_FATAL_ERROR;
        }

        if (SetIndividualExternal(&rsa->q, &key->q) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("rsa q key error");
            return WOLFSSL_FATAL_ERROR;
        }

    #ifndef RSA_LOW_MEM
        if (SetIndividualExternal(&rsa->dmp1, &key->dP) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("rsa dP key error");
            return WOLFSSL_FATAL_ERROR;
        }

        if (SetIndividualExternal(&rsa->dmq1, &key->dQ) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("rsa dQ key error");
            return WOLFSSL_FATAL_ERROR;
        }

        if (SetIndividualExternal(&rsa->iqmp, &key->u) != WOLFSSL_SUCCESS) {
           WOLFSSL_MSG("rsa u key error");
            return WOLFSSL_FATAL_ERROR;
        }
    #endif /* !RSA_LOW_MEM */
    }
    rsa->exSet = 1;

    return WOLFSSL_SUCCESS;
}
#endif /* !HAVE_USER_RSA && !HAVE_FAST_RSA &&
        * (OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL) */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
static void InitwolfSSL_Rsa(WOLFSSL_RSA* rsa)
{
    if (rsa) {
        XMEMSET(rsa, 0, sizeof(WOLFSSL_RSA));
    }
}


void wolfSSL_RSA_free(WOLFSSL_RSA* rsa)
{
    WOLFSSL_ENTER("wolfSSL_RSA_free");

    if (rsa) {
#if defined(OPENSSL_EXTRA_X509_SMALL) || defined(OPENSSL_EXTRA)
        int doFree = 0;
#endif
        void* heap = rsa->heap;

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
        wolfSSL_CRYPTO_cleanup_ex_data(&rsa->ex_data);
#endif
#if defined(OPENSSL_EXTRA_X509_SMALL) || defined(OPENSSL_EXTRA)
    #ifndef SINGLE_THREADED
        if (wc_LockMutex(&rsa->refMutex) != 0) {
            WOLFSSL_MSG("Couldn't lock rsa mutex");
            return;
        }
    #endif

        /* only free if all references to it are done */
        rsa->refCount--;
        if (rsa->refCount == 0) {
            doFree = 1;
        }
    #ifndef SINGLE_THREADED
        wc_UnLockMutex(&rsa->refMutex);
    #endif

        if (!doFree) {
            return;
        }

    #ifndef SINGLE_THREADED
        wc_FreeMutex(&rsa->refMutex);
    #endif
#endif

        if (rsa->internal) {
#if !defined(HAVE_FIPS) && !defined(HAVE_USER_RSA) && \
    !defined(HAVE_FAST_RSA) && defined(WC_RSA_BLINDING)
            WC_RNG* rng;

            /* check if RNG is owned before freeing it */
            if (rsa->ownRng) {
                rng = ((RsaKey*)rsa->internal)->rng;
                if (rng != NULL && rng != wolfssl_get_global_rng()) {
                    wc_FreeRng(rng);
                    XFREE(rng, heap, DYNAMIC_TYPE_RNG);
                }
            }
#endif /* WC_RSA_BLINDING */
            wc_FreeRsaKey((RsaKey*)rsa->internal);
            XFREE(rsa->internal, heap, DYNAMIC_TYPE_RSA);
            rsa->internal = NULL;
        }
        wolfSSL_BN_free(rsa->iqmp);
        wolfSSL_BN_free(rsa->dmq1);
        wolfSSL_BN_free(rsa->dmp1);
        wolfSSL_BN_free(rsa->q);
        wolfSSL_BN_free(rsa->p);
        wolfSSL_BN_free(rsa->d);
        wolfSSL_BN_free(rsa->e);
        wolfSSL_BN_free(rsa->n);

    #ifdef WC_RSA_BLINDING
        if (rsa->rng && wc_FreeRng(rsa->rng) != 0) {
            WOLFSSL_MSG("Issue freeing rng");
        }
        XFREE(rsa->rng, heap, DYNAMIC_TYPE_RNG);
    #endif

#if defined(OPENSSL_EXTRA) && !defined(WOLFCRYPT_ONLY)
        if (rsa->meth) {
            wolfSSL_RSA_meth_free(rsa->meth);
        }
#endif

        InitwolfSSL_Rsa(rsa);  /* set back to NULLs for safety */

        XFREE(rsa, heap, DYNAMIC_TYPE_RSA);
        (void)heap;

        /* rsa = NULL, don't try to access or double free it */
    }
}

WOLFSSL_RSA* wolfSSL_RSA_new_ex(void* heap, int devId)
{
    WOLFSSL_RSA* external;
    RsaKey* key;

    WOLFSSL_ENTER("wolfSSL_RSA_new");

    key = (RsaKey*)XMALLOC(sizeof(RsaKey), heap, DYNAMIC_TYPE_RSA);
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_RSA_new malloc RsaKey failure");
        return NULL;
    }

    external = (WOLFSSL_RSA*)XMALLOC(sizeof(WOLFSSL_RSA), heap,
                                     DYNAMIC_TYPE_RSA);
    if (external == NULL) {
        WOLFSSL_MSG("wolfSSL_RSA_new malloc WOLFSSL_RSA failure");
        XFREE(key, heap, DYNAMIC_TYPE_RSA);
        return NULL;
    }

    external->heap = heap;
    InitwolfSSL_Rsa(external);

#if defined(OPENSSL_EXTRA_X509_SMALL) || defined(OPENSSL_EXTRA)
    external->refCount = 1;
#ifndef SINGLE_THREADED
    if (wc_InitMutex(&external->refMutex) != 0) {
        WOLFSSL_MSG("wc_InitMutex WOLFSSL_RSA failure");
        XFREE(external, heap, DYNAMIC_TYPE_RSA);
        XFREE(key, heap, DYNAMIC_TYPE_RSA);
        return NULL;
    }
#endif
#endif

    if (wc_InitRsaKey_ex(key, heap, devId) != 0) {
        WOLFSSL_MSG("InitRsaKey WOLFSSL_RSA failure");
        XFREE(external, heap, DYNAMIC_TYPE_RSA);
        XFREE(key, heap, DYNAMIC_TYPE_RSA);
        return NULL;
    }

#if !defined(HAVE_FIPS) && !defined(HAVE_USER_RSA) && \
    !defined(HAVE_FAST_RSA) && defined(WC_RSA_BLINDING)
    {
        WC_RNG* rng;

        rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), heap, DYNAMIC_TYPE_RNG);
        if (rng != NULL && wc_InitRng_ex(rng, heap, devId) != 0) {
            WOLFSSL_MSG("InitRng failure, attempting to use global RNG");
            XFREE(rng, heap, DYNAMIC_TYPE_RNG);
            rng = NULL;
        }

        external->ownRng = 1;
        if (rng == NULL) {
            rng = wolfssl_get_global_rng();
            external->ownRng = 0;
        }

        if (rng == NULL) {
            WOLFSSL_MSG("wolfSSL_RSA_new no WC_RNG for blinding");
            XFREE(external, heap, DYNAMIC_TYPE_RSA);
            XFREE(key, heap, DYNAMIC_TYPE_RSA);
            return NULL;
        }

        wc_RsaSetRNG(key, rng);
    }
#else
    XMEMSET(key, 0, sizeof(RsaKey));
#endif /* WC_RSA_BLINDING */

    external->internal = key;
    external->inSet = 0;
    return external;
}

WOLFSSL_RSA* wolfSSL_RSA_new(void)
{
    return wolfSSL_RSA_new_ex(NULL, INVALID_DEVID);
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#endif /* !NO_RSA */

/*******************************************************************************
 * END OF RSA API
 ******************************************************************************/


/*******************************************************************************
 * START OF DSA API
 ******************************************************************************/

#ifndef NO_DSA

#if defined(OPENSSL_EXTRA) && defined(XFPRINTF) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM)
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_DSA_print_fp(XFILE fp, WOLFSSL_DSA* dsa, int indent)
{
    int ret = WOLFSSL_SUCCESS;
    int pBits;

    WOLFSSL_ENTER("wolfSSL_DSA_print_fp");

    if (fp == XBADFILE || dsa == NULL) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS && dsa->p != NULL) {
        pBits = wolfSSL_BN_num_bits(dsa->p);
        if (pBits == WOLFSSL_FAILURE) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            XFPRINTF(fp, "%*s", indent, "");
            XFPRINTF(fp, "Private-Key: (%d bit)\n", pBits);
        }
    }
    if (ret == WOLFSSL_SUCCESS && dsa->priv_key != NULL) {
        ret = PrintBNFieldFp(fp, indent, "priv", dsa->priv_key);
    }
    if (ret == WOLFSSL_SUCCESS && dsa->pub_key != NULL) {
        ret = PrintBNFieldFp(fp, indent, "pub", dsa->pub_key);
    }
    if (ret == WOLFSSL_SUCCESS && dsa->p != NULL) {
        ret = PrintBNFieldFp(fp, indent, "P", dsa->p);
    }
    if (ret == WOLFSSL_SUCCESS && dsa->q != NULL) {
        ret = PrintBNFieldFp(fp, indent, "Q", dsa->q);
    }
    if (ret == WOLFSSL_SUCCESS && dsa->g != NULL) {
        ret = PrintBNFieldFp(fp, indent, "G", dsa->g);
    }

    WOLFSSL_LEAVE("wolfSSL_DSA_print_fp", ret);

    return ret;
}
#endif /* OPENSSL_EXTRA && XSNPRINTF && !NO_FILESYSTEM && NO_STDIO_FILESYSTEM */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
static void InitwolfSSL_DSA(WOLFSSL_DSA* dsa)
{
    if (dsa) {
        dsa->p        = NULL;
        dsa->q        = NULL;
        dsa->g        = NULL;
        dsa->pub_key  = NULL;
        dsa->priv_key = NULL;
        dsa->internal = NULL;
        dsa->inSet    = 0;
        dsa->exSet    = 0;
    }
}


WOLFSSL_DSA* wolfSSL_DSA_new(void)
{
    WOLFSSL_DSA* external;
    DsaKey*     key;

    WOLFSSL_MSG("wolfSSL_DSA_new");

    key = (DsaKey*) XMALLOC(sizeof(DsaKey), NULL, DYNAMIC_TYPE_DSA);
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_DSA_new malloc DsaKey failure");
        return NULL;
    }

    external = (WOLFSSL_DSA*) XMALLOC(sizeof(WOLFSSL_DSA), NULL,
                                    DYNAMIC_TYPE_DSA);
    if (external == NULL) {
        WOLFSSL_MSG("wolfSSL_DSA_new malloc WOLFSSL_DSA failure");
        XFREE(key, NULL, DYNAMIC_TYPE_DSA);
        return NULL;
    }

    InitwolfSSL_DSA(external);
    if (wc_InitDsaKey(key) != 0) {
        WOLFSSL_MSG("wolfSSL_DSA_new InitDsaKey failure");
        XFREE(key, NULL, DYNAMIC_TYPE_DSA);
        wolfSSL_DSA_free(external);
        return NULL;
    }
    external->internal = key;

    return external;
}


void wolfSSL_DSA_free(WOLFSSL_DSA* dsa)
{
    WOLFSSL_MSG("wolfSSL_DSA_free");

    if (dsa) {
        if (dsa->internal) {
            FreeDsaKey((DsaKey*)dsa->internal);
            XFREE(dsa->internal, NULL, DYNAMIC_TYPE_DSA);
            dsa->internal = NULL;
        }
        wolfSSL_BN_free(dsa->priv_key);
        wolfSSL_BN_free(dsa->pub_key);
        wolfSSL_BN_free(dsa->g);
        wolfSSL_BN_free(dsa->q);
        wolfSSL_BN_free(dsa->p);
        InitwolfSSL_DSA(dsa);  /* set back to NULLs for safety */

        XFREE(dsa, NULL, DYNAMIC_TYPE_DSA);

        /* dsa = NULL, don't try to access or double free it */
    }
}

/* wolfSSL -> OpenSSL */
int SetDsaExternal(WOLFSSL_DSA* dsa)
{
    DsaKey* key;
    WOLFSSL_MSG("Entering SetDsaExternal");

    if (dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("dsa key NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    key = (DsaKey*)dsa->internal;

    if (SetIndividualExternal(&dsa->p, &key->p) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("dsa p key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&dsa->q, &key->q) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("dsa q key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&dsa->g, &key->g) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("dsa g key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&dsa->pub_key, &key->y) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("dsa y key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&dsa->priv_key, &key->x) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("dsa x key error");
        return WOLFSSL_FATAL_ERROR;
    }

    dsa->exSet = 1;

    return WOLFSSL_SUCCESS;
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA
/* Openssl -> WolfSSL */
int SetDsaInternal(WOLFSSL_DSA* dsa)
{
    DsaKey* key;
    WOLFSSL_MSG("Entering SetDsaInternal");

    if (dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("dsa key NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    key = (DsaKey*)dsa->internal;

    if (dsa->p != NULL &&
        SetIndividualInternal(dsa->p, &key->p) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa p key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (dsa->q != NULL &&
        SetIndividualInternal(dsa->q, &key->q) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa q key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (dsa->g != NULL &&
        SetIndividualInternal(dsa->g, &key->g) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa g key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (dsa->pub_key != NULL) {
        if (SetIndividualInternal(dsa->pub_key, &key->y) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("rsa pub_key error");
            return WOLFSSL_FATAL_ERROR;
        }

        /* public key */
        key->type = DSA_PUBLIC;
    }

    if (dsa->priv_key != NULL) {
        if (SetIndividualInternal(dsa->priv_key, &key->x) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("rsa priv_key error");
            return WOLFSSL_FATAL_ERROR;
        }

        /* private key */
        key->type = DSA_PRIVATE;
    }

    dsa->inSet = 1;

    return WOLFSSL_SUCCESS;
}

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_DSA_generate_key(WOLFSSL_DSA* dsa)
{
    int ret = WOLFSSL_FAILURE;

    WOLFSSL_ENTER("wolfSSL_DSA_generate_key");

    if (dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("Bad arguments");
        return WOLFSSL_FAILURE;
    }

    if (dsa->inSet == 0) {
        WOLFSSL_MSG("No DSA internal set, do it");

        if (SetDsaInternal(dsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetDsaInternal failed");
            return ret;
        }
    }

#ifdef WOLFSSL_KEY_GEN
    {
        int initTmpRng = 0;
        WC_RNG *rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
        WC_RNG *tmpRNG;
#else
        WC_RNG tmpRNG[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
        tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
        if (tmpRNG == NULL)
            return WOLFSSL_FATAL_ERROR;
#endif
        if (wc_InitRng(tmpRNG) == 0) {
            rng = tmpRNG;
            initTmpRng = 1;
        }
        else {
            WOLFSSL_MSG("Bad RNG Init, trying global");
            rng = wolfssl_get_global_rng();
        }

        if (rng) {
            /* These were allocated above by SetDsaInternal(). They should
             * be cleared before wc_MakeDsaKey() which reinitializes
             * x and y. */
            mp_clear(&((DsaKey*)dsa->internal)->x);
            mp_clear(&((DsaKey*)dsa->internal)->y);

            if (wc_MakeDsaKey(rng, (DsaKey*)dsa->internal) != MP_OKAY)
                WOLFSSL_MSG("wc_MakeDsaKey failed");
            else if (SetDsaExternal(dsa) != WOLFSSL_SUCCESS)
                WOLFSSL_MSG("SetDsaExternal failed");
            else
                ret = WOLFSSL_SUCCESS;
        }

        if (initTmpRng)
            wc_FreeRng(tmpRNG);

#ifdef WOLFSSL_SMALL_STACK
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
#endif
    }
#else /* WOLFSSL_KEY_GEN */
    WOLFSSL_MSG("No Key Gen built in");
#endif
    return ret;
}


/* Returns a pointer to a new WOLFSSL_DSA structure on success and NULL on fail
 */
WOLFSSL_DSA* wolfSSL_DSA_generate_parameters(int bits, unsigned char* seed,
        int seedLen, int* counterRet, unsigned long* hRet,
        WOLFSSL_BN_CB cb, void* CBArg)
{
    WOLFSSL_DSA* dsa;

    WOLFSSL_ENTER("wolfSSL_DSA_generate_parameters()");

    (void)cb;
    (void)CBArg;
    dsa = wolfSSL_DSA_new();
    if (dsa == NULL) {
        return NULL;
    }

    if (wolfSSL_DSA_generate_parameters_ex(dsa, bits, seed, seedLen,
                                  counterRet, hRet, NULL) != WOLFSSL_SUCCESS) {
        wolfSSL_DSA_free(dsa);
        return NULL;
    }

    return dsa;
}


/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_DSA_generate_parameters_ex(WOLFSSL_DSA* dsa, int bits,
                                       unsigned char* seed, int seedLen,
                                       int* counterRet,
                                       unsigned long* hRet, void* cb)
{
    int ret = WOLFSSL_FAILURE;

    (void)bits;
    (void)seed;
    (void)seedLen;
    (void)counterRet;
    (void)hRet;
    (void)cb;

    WOLFSSL_ENTER("wolfSSL_DSA_generate_parameters_ex");

    if (dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("Bad arguments");
        return WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_KEY_GEN
    {
        int initTmpRng = 0;
        WC_RNG *rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
        WC_RNG *tmpRNG;
#else
        WC_RNG tmpRNG[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
        tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
        if (tmpRNG == NULL)
            return WOLFSSL_FATAL_ERROR;
#endif
        if (wc_InitRng(tmpRNG) == 0) {
            rng = tmpRNG;
            initTmpRng = 1;
        }
        else {
            WOLFSSL_MSG("Bad RNG Init, trying global");
            rng = wolfssl_get_global_rng();
        }

        if (rng) {
            if (wc_MakeDsaParameters(rng, bits,
                                     (DsaKey*)dsa->internal) != MP_OKAY)
                WOLFSSL_MSG("wc_MakeDsaParameters failed");
            else if (SetDsaExternal(dsa) != WOLFSSL_SUCCESS)
                WOLFSSL_MSG("SetDsaExternal failed");
            else
                ret = WOLFSSL_SUCCESS;
        }

        if (initTmpRng)
            wc_FreeRng(tmpRNG);

#ifdef WOLFSSL_SMALL_STACK
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
#endif
    }
#else /* WOLFSSL_KEY_GEN */
    WOLFSSL_MSG("No Key Gen built in");
#endif

    return ret;
}

void wolfSSL_DSA_get0_pqg(const WOLFSSL_DSA *d, const WOLFSSL_BIGNUM **p,
        const WOLFSSL_BIGNUM **q, const WOLFSSL_BIGNUM **g)
{
    WOLFSSL_ENTER("wolfSSL_DSA_get0_pqg");
    if (d != NULL) {
        if (p != NULL)
            *p = d->p;
        if (q != NULL)
            *q = d->q;
        if (g != NULL)
            *g = d->g;
    }
}

int wolfSSL_DSA_set0_pqg(WOLFSSL_DSA *d, WOLFSSL_BIGNUM *p,
        WOLFSSL_BIGNUM *q, WOLFSSL_BIGNUM *g)
{
    WOLFSSL_ENTER("wolfSSL_DSA_set0_pqg");
    if (d == NULL || p == NULL || q == NULL || g == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }
    wolfSSL_BN_free(d->p);
    wolfSSL_BN_free(d->q);
    wolfSSL_BN_free(d->g);
    d->p = p;
    d->q = q;
    d->g = g;
    return WOLFSSL_SUCCESS;
}

void wolfSSL_DSA_get0_key(const WOLFSSL_DSA *d,
        const WOLFSSL_BIGNUM **pub_key, const WOLFSSL_BIGNUM **priv_key)
{
    WOLFSSL_ENTER("wolfSSL_DSA_get0_key");
    if (d != NULL) {
        if (pub_key != NULL)
            *pub_key = d->pub_key;
        if (priv_key != NULL)
            *priv_key = d->priv_key;
    }
}

int wolfSSL_DSA_set0_key(WOLFSSL_DSA *d, WOLFSSL_BIGNUM *pub_key,
        WOLFSSL_BIGNUM *priv_key)
{
    WOLFSSL_ENTER("wolfSSL_DSA_set0_key");

    /* The private key may be NULL */
    if (pub_key == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    wolfSSL_BN_free(d->pub_key);
    wolfSSL_BN_free(d->priv_key);
    d->pub_key = pub_key;
    d->priv_key = priv_key;

    return WOLFSSL_SUCCESS;
}

WOLFSSL_DSA_SIG* wolfSSL_DSA_SIG_new(void)
{
    WOLFSSL_DSA_SIG* sig;
    WOLFSSL_ENTER("wolfSSL_DSA_SIG_new");
    sig = (WOLFSSL_DSA_SIG*)XMALLOC(sizeof(WOLFSSL_DSA_SIG), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (sig)
        XMEMSET(sig, 0, sizeof(WOLFSSL_DSA_SIG));
    return sig;
}

void wolfSSL_DSA_SIG_free(WOLFSSL_DSA_SIG *sig)
{
    WOLFSSL_ENTER("wolfSSL_DSA_SIG_free");
    if (sig) {
        if (sig->r) {
            wolfSSL_BN_free(sig->r);
        }
        if (sig->s) {
            wolfSSL_BN_free(sig->s);
        }
        XFREE(sig, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

void wolfSSL_DSA_SIG_get0(const WOLFSSL_DSA_SIG *sig,
        const WOLFSSL_BIGNUM **r, const WOLFSSL_BIGNUM **s)
{
    WOLFSSL_ENTER("wolfSSL_DSA_SIG_get0");
    if (sig != NULL) {
        *r = sig->r;
        *s = sig->s;
    }
}

int wolfSSL_DSA_SIG_set0(WOLFSSL_DSA_SIG *sig, WOLFSSL_BIGNUM *r,
        WOLFSSL_BIGNUM *s)
{
    WOLFSSL_ENTER("wolfSSL_DSA_SIG_set0");
    if (r == NULL || s == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    wolfSSL_BN_clear_free(sig->r);
    wolfSSL_BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;

    return WOLFSSL_SUCCESS;
}

#ifndef HAVE_SELFTEST
/**
 *
 * @param sig The input signature to encode
 * @param out The output buffer. If *out is NULL then a new buffer is
 *            allocated. Otherwise the output is written to the buffer.
 * @return length on success and -1 on error
 */
int wolfSSL_i2d_DSA_SIG(const WOLFSSL_DSA_SIG *sig, byte **out)
{
    /* Space for sequence + two asn ints */
    byte buf[MAX_SEQ_SZ + 2*(ASN_TAG_SZ + MAX_LENGTH_SZ + DSA_MAX_HALF_SIZE)];
    word32 bufLen = sizeof(buf);

    WOLFSSL_ENTER("wolfSSL_i2d_DSA_SIG");

    if (sig == NULL || sig->r == NULL || sig->s == NULL ||
            out == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    if (StoreECC_DSA_Sig(buf, &bufLen,
            (mp_int*)sig->r->internal, (mp_int*)sig->s->internal) != 0) {
        WOLFSSL_MSG("StoreECC_DSA_Sig error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (*out == NULL) {
        byte* tmp = (byte*)XMALLOC(bufLen, NULL, DYNAMIC_TYPE_ASN1);
        if (tmp == NULL) {
            WOLFSSL_MSG("malloc error");
            return WOLFSSL_FATAL_ERROR;
        }
        *out = tmp;
    }

   XMEMCPY(*out, buf, bufLen);

    return (int)bufLen;
}

/**
 * Same as wolfSSL_DSA_SIG_new but also initializes the internal bignums as well.
 * @return New WOLFSSL_DSA_SIG with r and s created as well
 */
static WOLFSSL_DSA_SIG* wolfSSL_DSA_SIG_new_bn(void)
{
    WOLFSSL_DSA_SIG* ret;

    if ((ret = wolfSSL_DSA_SIG_new()) == NULL) {
        WOLFSSL_MSG("wolfSSL_DSA_SIG_new error");
        return NULL;
    }

    if ((ret->r = wolfSSL_BN_new()) == NULL) {
        WOLFSSL_MSG("wolfSSL_BN_new error");
        wolfSSL_DSA_SIG_free(ret);
        return NULL;
    }

    if ((ret->s = wolfSSL_BN_new()) == NULL) {
        WOLFSSL_MSG("wolfSSL_BN_new error");
        wolfSSL_DSA_SIG_free(ret);
        return NULL;
    }

    return ret;
}

/**
 * This parses a DER encoded ASN.1 structure. The ASN.1 encoding is:
 * ASN1_SEQUENCE
 *   ASN1_INTEGER (DSA r)
 *   ASN1_INTEGER (DSA s)
 * Alternatively, if the input is DSA_160_SIG_SIZE or DSA_256_SIG_SIZE in
 * length then this API interprets this as two unsigned binary numbers.
 * @param sig    If non-null then free'd first and then newly created
 *               WOLFSSL_DSA_SIG is assigned
 * @param pp     Input buffer that is moved forward on success
 * @param length Length of input buffer
 * @return Newly created WOLFSSL_DSA_SIG on success or NULL on failure
 */
WOLFSSL_DSA_SIG* wolfSSL_d2i_DSA_SIG(WOLFSSL_DSA_SIG **sig,
        const unsigned char **pp, long length)
{
    WOLFSSL_DSA_SIG* ret;
    mp_int* r;
    mp_int* s;

    WOLFSSL_ENTER("wolfSSL_d2i_DSA_SIG");

    if (pp == NULL || *pp == NULL || length < 0) {
        WOLFSSL_MSG("Bad function arguments");
        return NULL;
    }

    if ((ret = wolfSSL_DSA_SIG_new_bn()) == NULL) {
        WOLFSSL_MSG("wolfSSL_DSA_SIG_new_bn error");
        return NULL;
    }

    r = (mp_int*)ret->r->internal;
    s = (mp_int*)ret->s->internal;

    if (DecodeECC_DSA_Sig(*pp, (word32)length, r, s) != 0) {
        if (length == DSA_160_SIG_SIZE || length == DSA_256_SIG_SIZE) {
            /* Two raw numbers of length/2 size each */
            if (mp_read_unsigned_bin(r, *pp, (int)length/2) != 0) {
                WOLFSSL_MSG("r mp_read_unsigned_bin error");
                wolfSSL_DSA_SIG_free(ret);
                return NULL;
            }

            if (mp_read_unsigned_bin(s, *pp + (length/2), (int)length/2) != 0) {
                WOLFSSL_MSG("s mp_read_unsigned_bin error");
                wolfSSL_DSA_SIG_free(ret);
                return NULL;
            }

            *pp += length;
        }
        else {
            WOLFSSL_MSG("DecodeECC_DSA_Sig error");
            wolfSSL_DSA_SIG_free(ret);
            return NULL;
        }
    }
    else {
        /* DecodeECC_DSA_Sig success move pointer forward */
#ifndef NO_STRICT_ECDSA_LEN
        *pp += length;
#else
        {
            /* We need to figure out how much to move by ourselves */
            word32 idx = 0;
            int len = 0;
            if (GetSequence(*pp, &idx, &len, (word32)length) < 0) {
                WOLFSSL_MSG("GetSequence error");
                wolfSSL_DSA_SIG_free(ret);
                return NULL;
            }
            *pp += len;
        }
#endif
    }

    if (sig != NULL) {
        if (*sig != NULL)
            wolfSSL_DSA_SIG_free(*sig);
        *sig = ret;
    }

    return ret;
}
#endif /* HAVE_SELFTEST */

/* return WOLFSSL_SUCCESS on success, < 0 otherwise */
int wolfSSL_DSA_do_sign(const unsigned char* d, unsigned char* sigRet,
                       WOLFSSL_DSA* dsa)
{
    int     ret = WOLFSSL_FATAL_ERROR;
    int     initTmpRng = 0;
    WC_RNG* rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRNG = NULL;
#else
    WC_RNG  tmpRNG[1];
#endif

    WOLFSSL_ENTER("wolfSSL_DSA_do_sign");

    if (d == NULL || sigRet == NULL || dsa == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return ret;
    }

    if (dsa->inSet == 0) {
        WOLFSSL_MSG("No DSA internal set, do it");
        if (SetDsaInternal(dsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetDsaInternal failed");
            return ret;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
    if (tmpRNG == NULL)
        return WOLFSSL_FATAL_ERROR;
#endif

    if (wc_InitRng(tmpRNG) == 0) {
        rng = tmpRNG;
        initTmpRng = 1;
    }
    else {
        WOLFSSL_MSG("Bad RNG Init, trying global");
        rng = wolfssl_get_global_rng();
    }

    if (rng) {
        if (wc_DsaSign(d, sigRet, (DsaKey*)dsa->internal, rng) < 0)
            WOLFSSL_MSG("DsaSign failed");
        else
            ret = WOLFSSL_SUCCESS;
    }

    if (initTmpRng)
        wc_FreeRng(tmpRNG);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
#endif

    return ret;
}

#ifndef HAVE_SELFTEST
WOLFSSL_DSA_SIG* wolfSSL_DSA_do_sign_ex(const unsigned char* digest,
                                        int inLen, WOLFSSL_DSA* dsa)
{
    byte sigBin[DSA_MAX_SIG_SIZE];
    const byte *tmp = sigBin;
    int sigLen;

    WOLFSSL_ENTER("wolfSSL_DSA_do_sign_ex");

    if (!digest || !dsa || inLen != WC_SHA_DIGEST_SIZE) {
        WOLFSSL_MSG("Bad function arguments");
        return NULL;
    }

    if (wolfSSL_DSA_do_sign(digest, sigBin, dsa) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_DSA_do_sign error");
        return NULL;
    }

    if (dsa->internal == NULL) {
        WOLFSSL_MSG("dsa->internal is null");
        return NULL;
    }

    sigLen = mp_unsigned_bin_size(&((DsaKey*)dsa->internal)->q);
    if (sigLen <= 0) {
        WOLFSSL_MSG("mp_unsigned_bin_size error");
        return NULL;
    }

    /* 2 * sigLen for the two points r and s */
    return wolfSSL_d2i_DSA_SIG(NULL, &tmp, 2 * sigLen);
}
#endif /* !HAVE_SELFTEST */

int wolfSSL_DSA_do_verify(const unsigned char* d, unsigned char* sig,
                        WOLFSSL_DSA* dsa, int *dsacheck)
{
    int    ret = WOLFSSL_FATAL_ERROR;

    WOLFSSL_ENTER("wolfSSL_DSA_do_verify");

    if (d == NULL || sig == NULL || dsa == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }
    if (dsa->inSet == 0)
    {
        WOLFSSL_MSG("No DSA internal set, do it");

        if (SetDsaInternal(dsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetDsaInternal failed");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    ret = DsaVerify(d, sig, (DsaKey*)dsa->internal, dsacheck);
    if (ret != 0 || *dsacheck != 1) {
        WOLFSSL_MSG("DsaVerify failed");
        return ret;
    }

    return WOLFSSL_SUCCESS;
}


int wolfSSL_DSA_bits(const WOLFSSL_DSA *d)
{
    if (!d)
        return WOLFSSL_FAILURE;
    if (!d->exSet && SetDsaExternal((WOLFSSL_DSA*)d) != WOLFSSL_SUCCESS)
        return WOLFSSL_FAILURE;
    return wolfSSL_BN_num_bits(d->p);
}

#ifndef HAVE_SELFTEST
int wolfSSL_DSA_do_verify_ex(const unsigned char* digest, int digest_len,
                             WOLFSSL_DSA_SIG* sig, WOLFSSL_DSA* dsa)
{
    int dsacheck, sz;
    byte sigBin[DSA_MAX_SIG_SIZE];
    byte* sigBinPtr = sigBin;
    DsaKey* key;
    int qSz;

    WOLFSSL_ENTER("wolfSSL_DSA_do_verify_ex");

    if (!digest || !sig || !dsa || digest_len != WC_SHA_DIGEST_SIZE) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    if (!sig->r || !sig->s) {
        WOLFSSL_MSG("No signature found in DSA_SIG");
        return WOLFSSL_FAILURE;
    }

    if (dsa->inSet == 0) {
        WOLFSSL_MSG("No DSA internal set, do it");
        if (SetDsaInternal(dsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetDsaInternal failed");
            return WOLFSSL_FAILURE;
        }
    }

    key = (DsaKey*)dsa->internal;

    if (key == NULL) {
        WOLFSSL_MSG("dsa->internal is null");
        return WOLFSSL_FAILURE;
    }

    qSz = mp_unsigned_bin_size(&key->q);
    if (qSz < 0 || qSz > DSA_MAX_HALF_SIZE) {
        WOLFSSL_MSG("mp_unsigned_bin_size error");
        return WOLFSSL_FAILURE;
    }

    /* read r */
    /* front pad with zeros */
    if ((sz = wolfSSL_BN_num_bytes(sig->r)) < 0 || sz > DSA_MAX_HALF_SIZE)
        return WOLFSSL_FAILURE;
    while (sz++ < qSz)
        *sigBinPtr++ = 0;
    if (wolfSSL_BN_bn2bin(sig->r, sigBinPtr) == WOLFSSL_FATAL_ERROR)
        return WOLFSSL_FAILURE;

    /* Move to s */
    sigBinPtr = sigBin + qSz;

    /* read s */
    /* front pad with zeros */
    if ((sz = wolfSSL_BN_num_bytes(sig->s)) < 0 || sz > DSA_MAX_HALF_SIZE)
        return WOLFSSL_FAILURE;
    while (sz++ < qSz)
        *sigBinPtr++ = 0;
    if (wolfSSL_BN_bn2bin(sig->s, sigBinPtr) == WOLFSSL_FATAL_ERROR)
        return WOLFSSL_FAILURE;

    if ((wolfSSL_DSA_do_verify(digest, sigBin, dsa, &dsacheck)
                                         != WOLFSSL_SUCCESS) || dsacheck != 1) {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* !HAVE_SELFTEST */

WOLFSSL_API int wolfSSL_i2d_DSAparams(const WOLFSSL_DSA* dsa,
    unsigned char** out)
{
    int ret = 0;
    word32 derLen = 0;
    int preAllocated = 1;
    DsaKey* key = NULL;

    WOLFSSL_ENTER("wolfSSL_i2d_DSAparams");

    if (dsa == NULL || dsa->internal == NULL || out == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        key = (DsaKey*)dsa->internal;
        ret = wc_DsaKeyToParamsDer_ex(key, NULL, &derLen);
        if (ret == LENGTH_ONLY_E) {
            ret = 0;
        }
    }
    if (ret == 0 && *out == NULL) {
        /* If we're allocating out for the caller, we don't increment out just
           past the end of the DER buffer. If out is already allocated, we do.
           (OpenSSL convention) */
        preAllocated = 0;
        *out = (unsigned char*)XMALLOC(derLen, key->heap, DYNAMIC_TYPE_OPENSSL);
        if (*out == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        ret = wc_DsaKeyToParamsDer_ex(key, *out, &derLen);
    }
    if (ret >= 0 && preAllocated == 1) {
        *out += derLen;
    }

    if (ret < 0 && preAllocated == 0) {
        XFREE(*out, key->heap, DYNAMIC_TYPE_OPENSSL);
    }

    WOLFSSL_LEAVE("wolfSSL_i2d_DSAparams", ret);

    return ret;
}

WOLFSSL_DSA* wolfSSL_d2i_DSAparams(WOLFSSL_DSA** dsa, const unsigned char** der,
    long derLen)
{
    WOLFSSL_DSA* ret = NULL;
    int err = 0;
    word32 idx = 0;
    int asnLen;
    DsaKey* internalKey = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_DSAparams");

    if (der == NULL || *der == NULL || derLen <= 0) {
        err = 1;
    }
    if (err == 0) {
        ret = wolfSSL_DSA_new();
        err = ret == NULL;
    }
    if (err == 0) {
        err = GetSequence(*der, &idx, &asnLen, (word32)derLen) <= 0;
    }
    if (err == 0) {
        internalKey = (DsaKey*)ret->internal;
        err = GetInt(&internalKey->p, *der, &idx, (word32)derLen) != 0;
    }
    if (err == 0) {
        err = GetInt(&internalKey->q, *der, &idx, (word32)derLen) != 0;
    }
    if (err == 0) {
        err = GetInt(&internalKey->g, *der, &idx, (word32)derLen) != 0;
    }
    if (err == 0) {
        err = SetIndividualExternal(&ret->p, &internalKey->p)
                != WOLFSSL_SUCCESS;
    }
    if (err == 0) {
        err = SetIndividualExternal(&ret->q, &internalKey->q)
                != WOLFSSL_SUCCESS;
    }
    if (err == 0) {
        err = SetIndividualExternal(&ret->g, &internalKey->g)
                != WOLFSSL_SUCCESS;
    }
    if (err == 0 && dsa != NULL) {
        *dsa = ret;
    }

    if (err != 0 && ret != NULL) {
        wolfSSL_DSA_free(ret);
        ret = NULL;
    }

    return ret;
}

#if defined(WOLFSSL_KEY_GEN)
#ifndef NO_BIO

/* Takes a DSA Privatekey and writes it out to a WOLFSSL_BIO
 * Returns WOLFSSL_SUCCESS or WOLFSSL_FAILURE
 */
int wolfSSL_PEM_write_bio_DSAPrivateKey(WOLFSSL_BIO* bio, WOLFSSL_DSA* dsa,
                                       const EVP_CIPHER* cipher,
                                       unsigned char* passwd, int len,
                                       wc_pem_password_cb* cb, void* arg)
{
    int ret = 0, der_max_len = 0, derSz = 0;
    byte *derBuf;
    WOLFSSL_EVP_PKEY* pkey;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_DSAPrivateKey");

    if (bio == NULL || dsa == NULL) {
        WOLFSSL_MSG("Bad Function Arguments");
        return WOLFSSL_FAILURE;
    }

    pkey = wolfSSL_EVP_PKEY_new_ex(bio->heap);
    if (pkey == NULL) {
        WOLFSSL_MSG("wolfSSL_EVP_PKEY_new_ex failed");
        return WOLFSSL_FAILURE;
    }

    pkey->type   = EVP_PKEY_DSA;
    pkey->dsa    = dsa;
    pkey->ownDsa = 0;

    /* 4 > size of pub, priv, p, q, g + ASN.1 additional information */
    der_max_len = MAX_DSA_PRIVKEY_SZ;

    derBuf = (byte*)XMALLOC(der_max_len, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        WOLFSSL_MSG("Malloc failed");
        wolfSSL_EVP_PKEY_free(pkey);
        return WOLFSSL_FAILURE;
    }

    /* convert key to der format */
    derSz = wc_DsaKeyToDer((DsaKey*)dsa->internal, derBuf, der_max_len);
    if (derSz < 0) {
        WOLFSSL_MSG("wc_DsaKeyToDer failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        wolfSSL_EVP_PKEY_free(pkey);
        return WOLFSSL_FAILURE;
    }

    pkey->pkey.ptr = (char*)XMALLOC(derSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (pkey->pkey.ptr == NULL) {
        WOLFSSL_MSG("key malloc failed");
        XFREE(derBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
        wolfSSL_EVP_PKEY_free(pkey);
        return WOLFSSL_FAILURE;
    }

    /* add der info to the evp key */
    pkey->pkey_sz = derSz;
    XMEMCPY(pkey->pkey.ptr, derBuf, derSz);
    XFREE(derBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);

    ret = wolfSSL_PEM_write_bio_PrivateKey(bio, pkey, cipher, passwd, len,
                                        cb, arg);
    wolfSSL_EVP_PKEY_free(pkey);

    return ret;
}

#ifndef HAVE_SELFTEST
/* Takes a DSA public key and writes it out to a WOLFSSL_BIO
 * Returns WOLFSSL_SUCCESS or WOLFSSL_FAILURE
 */
int wolfSSL_PEM_write_bio_DSA_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_DSA* dsa)
{
    int ret = 0;
    WOLFSSL_EVP_PKEY* pkey;
    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_DSA_PUBKEY");

    if (bio == NULL || dsa == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    pkey = wolfSSL_EVP_PKEY_new_ex(bio->heap);
    if (pkey == NULL) {
        WOLFSSL_MSG("wolfSSL_EVP_PKEY_new_ex failed");
        return WOLFSSL_FAILURE;
    }

    pkey->type   = EVP_PKEY_DSA;
    pkey->dsa    = dsa;
    pkey->ownDsa = 0;

    ret = WriteBioPUBKEY(bio, pkey);
    wolfSSL_EVP_PKEY_free(pkey);
    return ret;
}
#endif /* HAVE_SELFTEST */
#endif /* !NO_BIO */

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_PEM_write_mem_DSAPrivateKey(WOLFSSL_DSA* dsa,
                                        const EVP_CIPHER* cipher,
                                        unsigned char* passwd, int passwdSz,
                                        unsigned char **pem, int *plen)
{
#if defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)
    byte *derBuf, *tmp, *cipherInfo = NULL;
    int  der_max_len = 0, derSz = 0;
    const int type = DSA_PRIVATEKEY_TYPE;
    const char* header = NULL;
    const char* footer = NULL;

    WOLFSSL_MSG("wolfSSL_PEM_write_mem_DSAPrivateKey");

    if (pem == NULL || plen == NULL || dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    if (wc_PemGetHeaderFooter(type, &header, &footer) != 0)
        return WOLFSSL_FAILURE;

    if (dsa->inSet == 0) {
        WOLFSSL_MSG("No DSA internal set, do it");

        if (SetDsaInternal(dsa) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetDsaInternal failed");
            return WOLFSSL_FAILURE;
        }
    }

    der_max_len = MAX_DSA_PRIVKEY_SZ;

    derBuf = (byte*)XMALLOC(der_max_len, NULL, DYNAMIC_TYPE_DER);
    if (derBuf == NULL) {
        WOLFSSL_MSG("malloc failed");
        return WOLFSSL_FAILURE;
    }

    /* Key to DER */
    derSz = wc_DsaKeyToDer((DsaKey*)dsa->internal, derBuf, der_max_len);
    if (derSz < 0) {
        WOLFSSL_MSG("wc_DsaKeyToDer failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        return WOLFSSL_FAILURE;
    }

    /* encrypt DER buffer if required */
    if (passwd != NULL && passwdSz > 0 && cipher != NULL) {
        int ret;

        ret = EncryptDerKey(derBuf, &derSz, cipher,
                            passwd, passwdSz, &cipherInfo, der_max_len);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("EncryptDerKey failed");
            XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
            return ret;
        }
        /* tmp buffer with a max size */
        *plen = (derSz * 2) + (int)XSTRLEN(header) + 1 +
            (int)XSTRLEN(footer) + 1 + HEADER_ENCRYPTED_KEY_SIZE;
    }
    else { /* tmp buffer with a max size */
        *plen = (derSz * 2) + (int)XSTRLEN(header) + 1 +
            (int)XSTRLEN(footer) + 1;
    }

    tmp = (byte*)XMALLOC(*plen, NULL, DYNAMIC_TYPE_PEM);
    if (tmp == NULL) {
        WOLFSSL_MSG("malloc failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        if (cipherInfo != NULL)
            XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);
        return WOLFSSL_FAILURE;
    }

    /* DER to PEM */
    *plen = wc_DerToPemEx(derBuf, derSz, tmp, *plen, cipherInfo, type);
    if (*plen <= 0) {
        WOLFSSL_MSG("wc_DerToPemEx failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        if (cipherInfo != NULL)
            XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);
        return WOLFSSL_FAILURE;
    }
    XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
    if (cipherInfo != NULL)
        XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);

    *pem = (byte*)XMALLOC((*plen)+1, NULL, DYNAMIC_TYPE_KEY);
    if (*pem == NULL) {
        WOLFSSL_MSG("malloc failed");
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        return WOLFSSL_FAILURE;
    }
    XMEMSET(*pem, 0, (*plen)+1);

    if (XMEMCPY(*pem, tmp, *plen) == NULL) {
        WOLFSSL_MSG("XMEMCPY failed");
        XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        return WOLFSSL_FAILURE;
    }
    XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);

    return WOLFSSL_SUCCESS;
#else
    (void)dsa;
    (void)cipher;
    (void)passwd;
    (void)passwdSz;
    (void)pem;
    (void)plen;
    return WOLFSSL_FAILURE;
#endif /* WOLFSSL_PEM_TO_DER || WOLFSSL_DER_TO_PEM */
}

#ifndef NO_FILESYSTEM
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_PEM_write_DSAPrivateKey(XFILE fp, WOLFSSL_DSA *dsa,
                                    const EVP_CIPHER *enc,
                                    unsigned char *kstr, int klen,
                                    wc_pem_password_cb *cb, void *u)
{
    byte *pem;
    int  plen, ret;

    (void)cb;
    (void)u;

    WOLFSSL_MSG("wolfSSL_PEM_write_DSAPrivateKey");

    if (fp == XBADFILE || dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    ret = wolfSSL_PEM_write_mem_DSAPrivateKey(dsa, enc, kstr, klen, &pem,
        &plen);
    if (ret != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_PEM_write_mem_DSAPrivateKey failed");
        return WOLFSSL_FAILURE;
    }

    ret = (int)XFWRITE(pem, plen, 1, fp);
    if (ret != 1) {
        WOLFSSL_MSG("DSA private key file write failed");
        return WOLFSSL_FAILURE;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    return WOLFSSL_SUCCESS;
}

#endif /* NO_FILESYSTEM */
#endif /* defined(WOLFSSL_KEY_GEN) */

#ifndef NO_FILESYSTEM
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
#ifndef NO_WOLFSSL_STUB
int wolfSSL_PEM_write_DSA_PUBKEY(XFILE fp, WOLFSSL_DSA *x)
{
    (void)fp;
    (void)x;
    WOLFSSL_STUB("PEM_write_DSA_PUBKEY");
    WOLFSSL_MSG("wolfSSL_PEM_write_DSA_PUBKEY not implemented");

    return WOLFSSL_FAILURE;
}
#endif
#endif /* NO_FILESYSTEM */

#ifndef NO_BIO

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && (!defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && defined(WOLFSSL_KEY_GEN))
/* Uses the same format of input as wolfSSL_PEM_read_bio_PrivateKey but expects
 * the results to be an DSA key.
 *
 * bio  structure to read DSA private key from
 * dsa  if not null is then set to the result
 * cb   password callback for reading PEM
 * pass password string
 *
 * returns a pointer to a new WOLFSSL_DSA structure on success and NULL on fail
 */
WOLFSSL_DSA* wolfSSL_PEM_read_bio_DSAPrivateKey(WOLFSSL_BIO* bio,
                                                WOLFSSL_DSA** dsa,
                                                wc_pem_password_cb* cb,
                                                void* pass)
{
    WOLFSSL_EVP_PKEY* pkey = NULL;
    WOLFSSL_DSA* local;
    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_DSAPrivateKey");


    pkey = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL, cb, pass);
    if (pkey == NULL) {
        WOLFSSL_MSG("Error in PEM_read_bio_PrivateKey");
         return NULL;
     }
     /* Since the WOLFSSL_DSA structure is being taken from WOLFSSL_EVP_PKEY the
     * flag indicating that the WOLFSSL_DSA structure is owned should be FALSE
     * to avoid having it free'd */
    pkey->ownDsa = 0;
    local = pkey->dsa;
    if (dsa != NULL) {
        *dsa = local;
    }
     wolfSSL_EVP_PKEY_free(pkey);
    return local;
}

/* Reads an DSA public key from a WOLFSSL_BIO into a WOLFSSL_DSA.
 * Returns WOLFSSL_SUCCESS or WOLFSSL_FAILURE
 */
WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSA_PUBKEY(WOLFSSL_BIO* bio,WOLFSSL_DSA** dsa,
                                             wc_pem_password_cb* cb, void* pass)
{
    WOLFSSL_EVP_PKEY* pkey;
    WOLFSSL_DSA* local;
    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_DSA_PUBKEY");

    pkey = wolfSSL_PEM_read_bio_PUBKEY(bio, NULL, cb, pass);
    if (pkey == NULL) {
        WOLFSSL_MSG("wolfSSL_PEM_read_bio_PUBKEY failed");
        return NULL;
    }

    /* Since the WOLFSSL_DSA structure is being taken from WOLFSSL_EVP_PKEY the
     * flag indicating that the WOLFSSL_DSA structure is owned should be FALSE
     * to avoid having it free'd */
    pkey->ownDsa = 0;
    local = pkey->dsa;
    if (dsa != NULL) {
        *dsa = local;
    }

    wolfSSL_EVP_PKEY_free(pkey);
    return local;
}
#endif /* (OPENSSL_EXTRA || OPENSSL_ALL) && (!NO_CERTS &&
          !NO_FILESYSTEM && WOLFSSL_KEY_GEN) */

#endif /* NO_BIO */

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* return WOLFSSL_SUCCESS if success, WOLFSSL_FATAL_ERROR if error */
int wolfSSL_DSA_LoadDer(WOLFSSL_DSA* dsa, const unsigned char* derBuf, int derSz)
{
    word32 idx = 0;
    int    ret;

    WOLFSSL_ENTER("wolfSSL_DSA_LoadDer");

    if (dsa == NULL || dsa->internal == NULL || derBuf == NULL || derSz <= 0) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    ret = DsaPrivateKeyDecode(derBuf, &idx, (DsaKey*)dsa->internal, derSz);
    if (ret < 0) {
        WOLFSSL_MSG("DsaPrivateKeyDecode failed");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetDsaExternal(dsa) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetDsaExternal failed");
        return WOLFSSL_FATAL_ERROR;
    }

    dsa->inSet = 1;

    return WOLFSSL_SUCCESS;
}

/* Loads DSA key from DER buffer. opt = DSA_LOAD_PRIVATE or DSA_LOAD_PUBLIC.
    returns 1 on success, or 0 on failure.  */
int wolfSSL_DSA_LoadDer_ex(WOLFSSL_DSA* dsa, const unsigned char* derBuf,
                                                            int derSz, int opt)
{
    word32 idx = 0;
    int    ret;

    WOLFSSL_ENTER("wolfSSL_DSA_LoadDer");

    if (dsa == NULL || dsa->internal == NULL || derBuf == NULL || derSz <= 0) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    if (opt == WOLFSSL_DSA_LOAD_PRIVATE) {
        ret = DsaPrivateKeyDecode(derBuf, &idx, (DsaKey*)dsa->internal, derSz);
    }
    else {
        ret = DsaPublicKeyDecode(derBuf, &idx, (DsaKey*)dsa->internal, derSz);
    }

    if (ret < 0 && opt == WOLFSSL_DSA_LOAD_PRIVATE) {
        WOLFSSL_MSG("DsaPrivateKeyDecode failed");
        return WOLFSSL_FATAL_ERROR;
    }
    else if (ret < 0 && opt == WOLFSSL_DSA_LOAD_PUBLIC) {
        WOLFSSL_MSG("DsaPublicKeyDecode failed");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetDsaExternal(dsa) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetDsaExternal failed");
        return WOLFSSL_FATAL_ERROR;
    }

    dsa->inSet = 1;

    return WOLFSSL_SUCCESS;
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA
#ifndef NO_BIO
WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSAparams(WOLFSSL_BIO *bp, WOLFSSL_DSA **x,
        wc_pem_password_cb *cb, void *u)
{
    WOLFSSL_DSA* dsa;
    DsaKey* key;
    int    length;
    unsigned char*  buf;
    word32 bufSz;
    int ret;
    word32 idx = 0;
    DerBuffer* pDer;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_DSAparams");

    ret = wolfSSL_BIO_get_mem_data(bp, &buf);
    if (ret <= 0) {
        WOLFSSL_LEAVE("wolfSSL_PEM_read_bio_DSAparams", ret);
        return NULL;
    }

    bufSz = (word32)ret;

    if (cb != NULL || u != NULL) {
        /*
         * cb is for a call back when encountering encrypted PEM files
         * if cb == NULL and u != NULL then u = null terminated password string
         */
        WOLFSSL_MSG("Not yet supporting call back or password for encrypted PEM");
    }

    if (PemToDer(buf, (long)bufSz, DSA_PARAM_TYPE, &pDer, NULL, NULL,
                    NULL) < 0 ) {
        WOLFSSL_MSG("Issue converting from PEM to DER");
        return NULL;
    }

    if (GetSequence(pDer->buffer, &idx, &length, pDer->length) < 0) {
        WOLFSSL_LEAVE("wolfSSL_PEM_read_bio_DSAparams", ret);
        FreeDer(&pDer);
        return NULL;
    }

    dsa = wolfSSL_DSA_new();
    if (dsa == NULL) {
        FreeDer(&pDer);
        WOLFSSL_MSG("Error creating DSA struct");
        return NULL;
    }

    key = (DsaKey*)dsa->internal;
    if (key == NULL) {
        FreeDer(&pDer);
        wolfSSL_DSA_free(dsa);
        WOLFSSL_MSG("Error finding DSA key struct");
        return NULL;
    }

    if (GetInt(&key->p,  pDer->buffer, &idx, pDer->length) < 0 ||
        GetInt(&key->q,  pDer->buffer, &idx, pDer->length) < 0 ||
        GetInt(&key->g,  pDer->buffer, &idx, pDer->length) < 0 ) {
        WOLFSSL_MSG("dsa key error");
        FreeDer(&pDer);
        wolfSSL_DSA_free(dsa);
        return NULL;
    }

    if (SetIndividualExternal(&dsa->p, &key->p) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("dsa p key error");
        FreeDer(&pDer);
        wolfSSL_DSA_free(dsa);
        return NULL;
    }

    if (SetIndividualExternal(&dsa->q, &key->q) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("dsa q key error");
        FreeDer(&pDer);
        wolfSSL_DSA_free(dsa);
        return NULL;
    }

    if (SetIndividualExternal(&dsa->g, &key->g) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("dsa g key error");
        FreeDer(&pDer);
        wolfSSL_DSA_free(dsa);
        return NULL;
    }

    if (x != NULL) {
        *x = dsa;
    }

    FreeDer(&pDer);
    return dsa;
}
#endif /* !NO_BIO */

#if !defined(NO_DH)
WOLFSSL_DH *wolfSSL_DSA_dup_DH(const WOLFSSL_DSA *dsa)
{
    WOLFSSL_DH* dh;
    DhKey*      key;

    WOLFSSL_ENTER("wolfSSL_DSA_dup_DH");

    if (dsa == NULL) {
        return NULL;
    }

    dh = wolfSSL_DH_new();
    if (dh == NULL) {
        return NULL;
    }
    key = (DhKey*)dh->internal;

    if (dsa->p != NULL &&
        SetIndividualInternal(((WOLFSSL_DSA*)dsa)->p, &key->p)
                                                           != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa p key error");
        wolfSSL_DH_free(dh);
        return NULL;
    }
    if (dsa->g != NULL &&
        SetIndividualInternal(((WOLFSSL_DSA*)dsa)->g, &key->g)
                                                           != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("rsa g key error");
        wolfSSL_DH_free(dh);
        return NULL;
    }

    if (SetIndividualExternal(&dh->p, &key->p) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("dsa p key error");
        wolfSSL_DH_free(dh);
        return NULL;
    }
    if (SetIndividualExternal(&dh->g, &key->g) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("dsa g key error");
        wolfSSL_DH_free(dh);
        return NULL;
    }

    return dh;
}
#endif /* !NO_DH */

#endif /* OPENSSL_EXTRA */

#endif /* !NO_DSA */

/*******************************************************************************
 * END OF DSA API
 ******************************************************************************/


/*******************************************************************************
 * START OF DH API
 ******************************************************************************/

#ifndef NO_DH

#ifdef OPENSSL_EXTRA

#ifndef NO_CERTS

#ifdef OPENSSL_ALL

int wolfSSL_DH_check(const WOLFSSL_DH *dh, int *codes)
{
    int isPrime = MP_NO, codeTmp = 0;
    WC_RNG rng;

    WOLFSSL_ENTER("wolfSSL_DH_check");
    if (dh == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (dh->g == NULL || dh->g->internal == NULL) {
        codeTmp = DH_NOT_SUITABLE_GENERATOR;
    }

    if (dh->p == NULL || dh->p->internal == NULL) {
        codeTmp = DH_CHECK_P_NOT_PRIME;
    }
    else
    {
        /* test if dh->p has prime */
        if (wc_InitRng(&rng) == 0) {
            mp_prime_is_prime_ex((mp_int*)dh->p->internal,8,&isPrime,&rng);
        }
        else {
            WOLFSSL_MSG("Error initializing rng");
            return WOLFSSL_FAILURE;
        }
        wc_FreeRng(&rng);
        if (isPrime != MP_YES) {
            codeTmp = DH_CHECK_P_NOT_PRIME;
        }
    }
    /* User may choose to enter NULL for codes if they don't want to check it*/
    if (codes != NULL) {
        *codes = codeTmp;
    }

    /* if codeTmp was set,some check was flagged invalid */
    if (codeTmp) {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}

#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
/* Converts DER encoded DH parameters to a WOLFSSL_DH structure.
 *
 * dh   : structure to copy DH parameters into.
 * pp   : DER encoded DH parameters
 * length   : length to copy
 *
 * Returns pointer to WOLFSSL_DH structure on success, or NULL on failure
 */
WOLFSSL_DH *wolfSSL_d2i_DHparams(WOLFSSL_DH **dh, const unsigned char **pp,
                                                                    long length)
{
    WOLFSSL_DH *newDH = NULL;
    int ret;
    word32 idx = 0;

    WOLFSSL_ENTER("wolfSSL_d2i_DHparams");

    if (pp == NULL || length <= 0) {
        WOLFSSL_MSG("bad argument");
        return NULL;
    }

    if ((newDH = wolfSSL_DH_new()) == NULL) {
        WOLFSSL_MSG("wolfSSL_DH_new() failed");
        return NULL;
    }

    ret = wc_DhKeyDecode(*pp, &idx, (DhKey*)newDH->internal, (word32)length);
    if (ret != 0) {
        WOLFSSL_MSG("DhKeyDecode() failed");
        wolfSSL_DH_free(newDH);
        return NULL;
    }
    newDH->inSet = 1;

    if (SetDhExternal(newDH) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetDhExternal failed");
        wolfSSL_DH_free(newDH);
        return NULL;
    }

    *pp += length;
    if (dh != NULL) {
        *dh = newDH;
    }

    return newDH;
}
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */

#define ASN_LEN_SIZE(l)             \
    (((l) < 128) ? 1 : (((l) < 256) ? 2 : 3))

/* Converts internal WOLFSSL_DH structure to DER encoded DH.
 *
 * dh   : structure to copy DH parameters from.
 * out  : DER buffer for DH parameters
 *
 * Returns size of DER on success and WOLFSSL_FAILURE if error
 */
int wolfSSL_i2d_DHparams(const WOLFSSL_DH *dh, unsigned char **out)
{
    word32 len;
    int ret = 0;
    int pSz;
    int gSz;

    WOLFSSL_ENTER("wolfSSL_i2d_DHparams");

    if (dh == NULL) {
        WOLFSSL_MSG("Bad parameters");
        return WOLFSSL_FAILURE;
    }

    /* Get total length */
    pSz = mp_unsigned_bin_size((mp_int*)dh->p->internal);
    gSz = mp_unsigned_bin_size((mp_int*)dh->g->internal);
    len = 1 + ASN_LEN_SIZE(pSz) + mp_leading_bit((mp_int*)dh->p->internal) +
          pSz +
          1 + ASN_LEN_SIZE(gSz) + mp_leading_bit((mp_int*)dh->g->internal) +
          gSz;

    /* Two bytes required for length if ASN.1 SEQ data greater than 127 bytes
     * and less than 256 bytes.
     */
    len += 1 + ASN_LEN_SIZE(len);

    if (out != NULL && *out != NULL) {
        ret = StoreDHparams(*out, &len, (mp_int*)dh->p->internal,
                                        (mp_int*)dh->g->internal);
        if (ret != MP_OKAY) {
            WOLFSSL_MSG("StoreDHparams error");
            len = 0;
        }
        else{
            *out += len;
        }
    }
    return (int)len;
}

#endif /* OPENSSL_ALL */

#endif /* !NO_CERTS */

long wolfSSL_set_tmp_dh(WOLFSSL *ssl, WOLFSSL_DH *dh)
{
    int pSz, gSz;
    byte *p, *g;
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_set_tmp_dh");

    if (!ssl || !dh)
        return BAD_FUNC_ARG;

    /* Get needed size for p and g */
    pSz = wolfSSL_BN_bn2bin(dh->p, NULL);
    gSz = wolfSSL_BN_bn2bin(dh->g, NULL);

    if (pSz <= 0 || gSz <= 0)
        return WOLFSSL_FATAL_ERROR;

    p = (byte*)XMALLOC(pSz, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (!p)
        return MEMORY_E;

    g = (byte*)XMALLOC(gSz, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (!g) {
        XFREE(p, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        return MEMORY_E;
    }

    pSz = wolfSSL_BN_bn2bin(dh->p, p);
    gSz = wolfSSL_BN_bn2bin(dh->g, g);

    if (pSz >= 0 && gSz >= 0) /* Conversion successful */
        ret = wolfSSL_SetTmpDH(ssl, p, pSz, g, gSz);

    XFREE(p, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(g, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);

    return pSz > 0 && gSz > 0 ? ret : WOLFSSL_FATAL_ERROR;
}


static void InitwolfSSL_DH(WOLFSSL_DH* dh)
{
    if (dh) {
        XMEMSET(dh, 0, sizeof(WOLFSSL_DH));
    }
}


WOLFSSL_DH* wolfSSL_DH_new(void)
{
    WOLFSSL_DH* external;
    DhKey*     key;

    WOLFSSL_ENTER("wolfSSL_DH_new");

    key = (DhKey*) XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_DH);
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_DH_new malloc DhKey failure");
        return NULL;
    }

    external = (WOLFSSL_DH*) XMALLOC(sizeof(WOLFSSL_DH), NULL,
                                    DYNAMIC_TYPE_DH);
    if (external == NULL) {
        WOLFSSL_MSG("wolfSSL_DH_new malloc WOLFSSL_DH failure");
        XFREE(key, NULL, DYNAMIC_TYPE_DH);
        return NULL;
    }

    InitwolfSSL_DH(external);

    external->refCount = 1;
#ifndef SINGLE_THREADED
    if (wc_InitMutex(&external->refMutex) != 0) {
        WOLFSSL_MSG("wc_InitMutex WOLFSSL_DH failure");
        XFREE(key, NULL, DYNAMIC_TYPE_DH);
        XFREE(external, NULL, DYNAMIC_TYPE_DH);
        return NULL;
    }
#endif

    if (wc_InitDhKey(key) != 0) {
        WOLFSSL_MSG("wolfSSL_DH_new InitDhKey failure");
        XFREE(key, NULL, DYNAMIC_TYPE_DH);
        XFREE(external, NULL, DYNAMIC_TYPE_DH);
        return NULL;
    }
    external->internal = key;
    external->priv_key = wolfSSL_BN_new();
    external->pub_key = wolfSSL_BN_new();

    return external;
}

WOLFSSL_DH* wolSSL_DH_new_by_nid(int nid)
{
    WOLFSSL_DH* dh = NULL;
    int err = 0;
#if defined(HAVE_PUBLIC_FFDHE) || (defined(HAVE_FIPS) && FIPS_VERSION_EQ(2,0))
    const DhParams* params = NULL;
    WOLFSSL_BIGNUM* pBn = NULL;
    WOLFSSL_BIGNUM* gBn = NULL;
    WOLFSSL_BIGNUM* qBn = NULL;
#elif !defined(HAVE_PUBLIC_FFDHE) && (!defined(HAVE_FIPS) || \
      FIPS_VERSION_GT(2,0))
    int name = 0;
#ifdef HAVE_FFDHE_Q
    int elements = ELEMENT_P | ELEMENT_G | ELEMENT_Q;
#else
    int elements = ELEMENT_P | ELEMENT_G;
#endif /* HAVE_FFDHE_Q */
#endif /* HAVE_PUBLIC_FFDHE || (HAVE_FIPS && HAVE_FIPS_VERSION == 2) */

    WOLFSSL_ENTER("wolfSSL_DH_new_by_nid");

/* HAVE_PUBLIC_FFDHE not required to expose wc_Dh_ffdhe* functions in FIPS v2
 * module */
#if defined(HAVE_PUBLIC_FFDHE) || (defined(HAVE_FIPS) && FIPS_VERSION_EQ(2,0))
    switch (nid) {
#ifdef HAVE_FFDHE_2048
    case NID_ffdhe2048:
        params = wc_Dh_ffdhe2048_Get();
        break;
#endif /* HAVE_FFDHE_2048 */
#ifdef HAVE_FFDHE_3072
    case NID_ffdhe3072:
        params = wc_Dh_ffdhe3072_Get();
        break;
#endif /* HAVE_FFDHE_3072 */
#ifdef HAVE_FFDHE_4096
    case NID_ffdhe4096:
        params = wc_Dh_ffdhe4096_Get();
        break;
#endif /* HAVE_FFDHE_4096 */
    default:
        break;
    }
    if (params == NULL) {
        WOLFSSL_MSG("Unable to find DH params for nid.");
        err = 1;
    }
    if (err == 0) {
        dh = wolfSSL_DH_new();
        if (dh == NULL) {
            WOLFSSL_MSG("Failed to create WOLFSSL_DH.");
            err = 1;
        }
    }
    if (err == 0) {
        pBn = wolfSSL_BN_bin2bn(params->p, params->p_len, NULL);
        if (pBn == NULL) {
            WOLFSSL_MSG("Error converting p hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
    if (err == 0) {
        gBn = wolfSSL_BN_bin2bn(params->g, params->g_len, NULL);
        if (gBn == NULL) {
            WOLFSSL_MSG("Error converting g hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
#ifdef HAVE_FFDHE_Q
    if (err == 0) {
        qBn = wolfSSL_BN_bin2bn(params->q, params->q_len, NULL);
        if (qBn == NULL) {
            WOLFSSL_MSG("Error converting q hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
#endif
#if defined(OPENSSL_ALL) || defined(OPENSSL_VERSION_NUMBER) && \
    OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (err == 0 && wolfSSL_DH_set0_pqg(dh, pBn, qBn, gBn) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Failed to set DH params.");
        err = 1;
    }
#else
    if (err == 0) {
        dh->p = pBn;
        dh->q = qBn;
        dh->g = gBn;
        if (SetDhInternal(dh) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Failed to set internal DH params.");
            err = 1;
        }
    }
#endif /* OPENSSL_ALL || OPENSSL_VERSION_NUMBER >= 0x10100000L */

    if (err == 1) {
        wolfSSL_BN_free(pBn);
        wolfSSL_BN_free(gBn);
        wolfSSL_BN_free(qBn);
    }
/* FIPS v2 and lower doesn't support wc_DhSetNamedKey. */
#elif !defined(HAVE_PUBLIC_FFDHE) && (!defined(HAVE_FIPS) || \
      FIPS_VERSION_GT(2,0))
    switch (nid) {
#ifdef HAVE_FFDHE_2048
    case NID_ffdhe2048:
       name = WC_FFDHE_2048;
        break;
#endif /* HAVE_FFDHE_2048 */
#ifdef HAVE_FFDHE_3072
    case NID_ffdhe3072:
        name = WC_FFDHE_3072;
        break;
#endif /* HAVE_FFDHE_3072 */
#ifdef HAVE_FFDHE_4096
    case NID_ffdhe4096:
        name = WC_FFDHE_4096;
        break;
#endif /* HAVE_FFDHE_4096 */
    default:
        err = 1;
        WOLFSSL_MSG("Unable to find DH params for nid.");
        break;
    }
    if (err == 0) {
        dh = wolfSSL_DH_new();
        if (dh == NULL) {
            WOLFSSL_MSG("Failed to create WOLFSSL_DH.");
            err = 1;
        }
    }
    if (err == 0 && wc_DhSetNamedKey((DhKey*)dh->internal, name) != 0) {
        WOLFSSL_MSG("wc_DhSetNamedKey failed.");
        err = 1;
    }
    if (err == 0 && SetDhExternal_ex(dh, elements) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Failed to set external DH params.");
        err = 1;
    }
#else
    /* Unsupported configuration. */
    err = 1;
#endif /* HAVE_PUBLIC_FFDHE || (HAVE_FIPS && HAVE_FIPS_VERSION == 2) */

    if (err == 1 && dh != NULL) {
        wolfSSL_DH_free(dh);
        dh = NULL;
    }

    WOLFSSL_LEAVE("wolfSSL_DH_new_by_nid", err);

    return dh;
}

void wolfSSL_DH_free(WOLFSSL_DH* dh)
{
    int doFree = 0;

    WOLFSSL_ENTER("wolfSSL_DH_free");

    if (dh) {

    #ifndef SINGLE_THREADED
        if (wc_LockMutex(&dh->refMutex) != 0) {
            WOLFSSL_MSG("Could not lock DH mutex");
        }
    #endif
        /* only free if all references to it are done */
        dh->refCount--;
        if (dh->refCount == 0) {
            doFree = 1;
        }
    #ifndef SINGLE_THREADED
        wc_UnLockMutex(&dh->refMutex);
    #endif

        if (doFree == 0) {
            return;
        }

        if (dh->internal) {
            wc_FreeDhKey((DhKey*)dh->internal);
            XFREE(dh->internal, NULL, DYNAMIC_TYPE_DH);
            dh->internal = NULL;
        }
        wolfSSL_BN_free(dh->priv_key);
        wolfSSL_BN_free(dh->pub_key);
        wolfSSL_BN_free(dh->g);
        wolfSSL_BN_free(dh->p);
        wolfSSL_BN_free(dh->q);
        InitwolfSSL_DH(dh);  /* set back to NULLs for safety */

        XFREE(dh, NULL, DYNAMIC_TYPE_DH);
    }
}

int wolfSSL_DH_up_ref(WOLFSSL_DH* dh)
{
    WOLFSSL_ENTER("wolfSSL_DH_up_ref");

    if (dh) {
    #ifndef SINGLE_THREADED
        if (wc_LockMutex(&dh->refMutex) != 0) {
            WOLFSSL_MSG("Failed to lock DH mutex");
        }
    #endif
        dh->refCount++;
    #ifndef SINGLE_THREADED
        wc_UnLockMutex(&dh->refMutex);
    #endif
        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}

int SetDhInternal(WOLFSSL_DH* dh)
{
    int            ret = WOLFSSL_FATAL_ERROR;
    int            pSz = 1024;
    int            gSz = 1024;
#ifdef WOLFSSL_DH_EXTRA
    int            privSz = 256; /* Up to 2048-bit */
    int            pubSz  = 256;
#endif
#ifdef WOLFSSL_SMALL_STACK
    unsigned char* p   = NULL;
    unsigned char* g   = NULL;
    #ifdef WOLFSSL_DH_EXTRA
        unsigned char* priv_key = NULL;
        unsigned char* pub_key = NULL;
    #endif
#else
    unsigned char  p[1024];
    unsigned char  g[1024];
    #ifdef WOLFSSL_DH_EXTRA
        unsigned char priv_key[256];
        unsigned char pub_key[256];
    #endif
#endif

    WOLFSSL_ENTER("SetDhInternal");

    if (dh == NULL || dh->p == NULL || dh->g == NULL)
        WOLFSSL_MSG("Bad function arguments");
    else if (wolfSSL_BN_bn2bin(dh->p, NULL) > pSz)
        WOLFSSL_MSG("Bad p internal size");
    else if (wolfSSL_BN_bn2bin(dh->g, NULL) > gSz)
        WOLFSSL_MSG("Bad g internal size");
#ifdef WOLFSSL_DH_EXTRA
    else if (wolfSSL_BN_bn2bin(dh->priv_key, NULL) > privSz)
        WOLFSSL_MSG("Bad private key internal size");
    else if (wolfSSL_BN_bn2bin(dh->pub_key, NULL) > privSz)
        WOLFSSL_MSG("Bad public key internal size");
#endif
    else {
    #ifdef WOLFSSL_SMALL_STACK
        p = (unsigned char*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        g = (unsigned char*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        #ifdef WOLFSSL_DH_EXTRA
            priv_key = (unsigned char*)XMALLOC(privSz, NULL,
                DYNAMIC_TYPE_PRIVATE_KEY);
            pub_key  = (unsigned char*)XMALLOC(pubSz, NULL,
                DYNAMIC_TYPE_PUBLIC_KEY);
        #endif

        if (p == NULL || g == NULL) {
            XFREE(p, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
            XFREE(g, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
            return ret;
        }
    #endif /* WOLFSSL_SMALL_STACK */

        /* Free so that mp_init's don't leak */
        wc_FreeDhKey((DhKey*)dh->internal);

    #ifdef WOLFSSL_DH_EXTRA
        privSz = wolfSSL_BN_bn2bin(dh->priv_key, priv_key);
        pubSz  = wolfSSL_BN_bn2bin(dh->pub_key,  pub_key);
        if (privSz <= 0) {
           WOLFSSL_MSG("No private key size.");
        }
        if (pubSz <= 0) {
            WOLFSSL_MSG("No public key size.");
        }
        if (privSz > 0 || pubSz > 0) {
            ret = wc_DhImportKeyPair((DhKey*)dh->internal, priv_key, privSz,
                                     pub_key, pubSz);
            if (ret == 0) {
                ret = WOLFSSL_SUCCESS;
            }
            else {
                WOLFSSL_MSG("Failed setting private or public key.");
                ret = WOLFSSL_FAILURE;
            }
        }
    #endif /* WOLFSSL_DH_EXTRA */

        pSz = wolfSSL_BN_bn2bin(dh->p, p);
        gSz = wolfSSL_BN_bn2bin(dh->g, g);

        if (pSz <= 0 || gSz <= 0)
            WOLFSSL_MSG("Bad BN2bin set");
        else if (wc_DhSetKey((DhKey*)dh->internal, p, pSz, g, gSz) < 0)
            WOLFSSL_MSG("Bad DH SetKey");
        else {
            dh->inSet = 1;
            ret = WOLFSSL_SUCCESS;
        }

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(p, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(g, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        #ifdef WOLFSSL_DH_EXTRA
            XFREE(priv_key, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
            XFREE(pub_key,  NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        #endif
    #endif
    }

    return ret;
}

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL) \
    || defined(WOLFSSL_OPENSSH) || defined(OPENSSL_EXTRA)

#ifdef WOLFSSL_DH_EXTRA
WOLFSSL_DH* wolfSSL_DH_dup(WOLFSSL_DH* dh)
{
    WOLFSSL_DH* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_DH_dup");

    if (!dh) {
        WOLFSSL_MSG("Bad parameter");
        return NULL;
    }

    if (dh->inSet == 0 && SetDhInternal(dh) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Bad DH set internal");
        return NULL;
    }

    if (!(ret = wolfSSL_DH_new())) {
        WOLFSSL_MSG("wolfSSL_DH_new error");
        return NULL;
    }

    if (wc_DhKeyCopy((DhKey*)dh->internal, (DhKey*)ret->internal) != MP_OKAY) {
        WOLFSSL_MSG("wc_DhKeyCopy error");
        wolfSSL_DH_free(ret);
        return NULL;
    }
    ret->inSet = 1;

    if (SetDhExternal(ret) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetDhExternal error");
        wolfSSL_DH_free(ret);
        return NULL;
    }

    return ret;
}
#endif /* WOLFSSL_DH_EXTRA */

/* Set the members of DhKey into WOLFSSL_DH
 * Specify elements to set via the 2nd parmeter
 */
int SetDhExternal_ex(WOLFSSL_DH *dh, int elm)
{
    DhKey *key;
    WOLFSSL_MSG("Entering SetDhExternal_ex");

    if (dh == NULL || dh->internal == NULL) {
        WOLFSSL_MSG("dh key NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    key = (DhKey*)dh->internal;

    if (elm & ELEMENT_P) {
        if (SetIndividualExternal(&dh->p, &key->p) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("dh param p error");
            return WOLFSSL_FATAL_ERROR;
        }
    }
    if (elm & ELEMENT_Q) {
        if (SetIndividualExternal(&dh->q, &key->q) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("dh param q error");
            return WOLFSSL_FATAL_ERROR;
        }
    }
    if (elm & ELEMENT_G) {
        if (SetIndividualExternal(&dh->g, &key->g) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("dh param g error");
            return WOLFSSL_FATAL_ERROR;
        }
    }
#ifdef WOLFSSL_DH_EXTRA
    if (elm & ELEMENT_PRV) {
        if (SetIndividualExternal(&dh->priv_key, &key->priv) !=
                                                      WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("No DH Private Key");
            return WOLFSSL_FATAL_ERROR;
        }
    }
    if (elm & ELEMENT_PUB) {
        if (SetIndividualExternal(&dh->pub_key, &key->pub) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("No DH Public Key");
            return WOLFSSL_FATAL_ERROR;
        }
    }
#endif /* WOLFSSL_DH_EXTRA */

    dh->exSet = 1;

    return WOLFSSL_SUCCESS;
}
/* Set the members of DhKey into WOLFSSL_DH
 * DhKey was populated from wc_DhKeyDecode
 * p, g, pub_key and pri_key are set.
 */
int SetDhExternal(WOLFSSL_DH *dh)
{
    int elements = ELEMENT_P | ELEMENT_G | ELEMENT_PUB | ELEMENT_PRV;
    WOLFSSL_MSG("Entering SetDhExternal");
    return SetDhExternal_ex(dh, elements);
}
#endif /* WOLFSSL_QT || OPENSSL_ALL || WOLFSSL_OPENSSH || OPENSSL_EXTRA */

/* return code compliant with OpenSSL :
 *   DH prime size in bytes if success, 0 if error
 */
int wolfSSL_DH_size(WOLFSSL_DH* dh)
{
    WOLFSSL_MSG("wolfSSL_DH_size");

    if (dh == NULL)
        return WOLFSSL_FATAL_ERROR;

    return wolfSSL_BN_num_bytes(dh->p);
}

/* This sets a big number with the 768-bit prime from RFC 2409.
 *
 * bn  if not NULL then the big number structure is used. If NULL then a new
 *     big number structure is created.
 *
 * Returns a WOLFSSL_BIGNUM structure on success and NULL with failure.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_768_prime(WOLFSSL_BIGNUM* bn)
{
    const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A63A3620FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_768_prime");

    if (wolfSSL_BN_hex2bn(&bn, prm) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error converting DH 768 prime to big number");
        return NULL;
    }

    return bn;
}

/* This sets a big number with the 1024-bit prime from RFC 2409.
 *
 * bn  if not NULL then the big number structure is used. If NULL then a new
 *     big number structure is created.
 *
 * Returns a WOLFSSL_BIGNUM structure on success and NULL with failure.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_1024_prime(WOLFSSL_BIGNUM* bn)
{
    const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE65381FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_1024_prime");

    if (wolfSSL_BN_hex2bn(&bn, prm) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error converting DH 1024 prime to big number");
        return NULL;
    }

    return bn;
}

/* This sets a big number with the 1536-bit prime from RFC 3526.
 *
 * bn  if not NULL then the big number structure is used. If NULL then a new
 *     big number structure is created.
 *
 * Returns a WOLFSSL_BIGNUM structure on success and NULL with failure.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_1536_prime(WOLFSSL_BIGNUM* bn)
{
    const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA237327FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_1536_prime");

    if (wolfSSL_BN_hex2bn(&bn, prm) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error converting DH 1536 prime to big number");
        return NULL;
    }

    return bn;
}

/* This sets a big number with the 2048-bit prime from RFC 3526.
 *
 * bn  if not NULL then the big number structure is used. If NULL then a new
 *     big number structure is created.
 *
 * Returns a WOLFSSL_BIGNUM structure on success and NULL with failure.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_2048_prime(WOLFSSL_BIGNUM* bn)
{
    const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28F"
        "B5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_2048_prime");

    if (wolfSSL_BN_hex2bn(&bn, prm) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error converting DH 2048 prime to big number");
        return NULL;
    }

    return bn;
}

/* This sets a big number with the 3072-bit prime from RFC 3526.
 *
 * bn  if not NULL then the big number structure is used. If NULL then a new
 *     big number structure is created.
 *
 * Returns a WOLFSSL_BIGNUM structure on success and NULL with failure.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_3072_prime(WOLFSSL_BIGNUM* bn)
{
    const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28F"
        "B5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33"
        "A85521ABDF1CBA64ECFB850458DBEF0A"
        "8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619D"
        "CEE3D2261AD2EE6BF12FFA06D98A0864"
        "D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E2"
        "08E24FA074E5AB3143DB5BFCE0FD108E"
        "4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_3072_prime");

    if (wolfSSL_BN_hex2bn(&bn, prm) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error converting DH 3072 prime to big number");
        return NULL;
    }

    return bn;
}

/* This sets a big number with the 4096-bit prime from RFC 3526.
 *
 * bn  if not NULL then the big number structure is used. If NULL then a new
 *     big number structure is created.
 *
 * Returns a WOLFSSL_BIGNUM structure on success and NULL with failure.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_4096_prime(WOLFSSL_BIGNUM* bn)
{
    const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28F"
        "B5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33"
        "A85521ABDF1CBA64ECFB850458DBEF0A"
        "8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619D"
        "CEE3D2261AD2EE6BF12FFA06D98A0864"
        "D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E2"
        "08E24FA074E5AB3143DB5BFCE0FD108E"
        "4B82D120A92108011A723C12A787E6D7"
        "88719A10BDBA5B2699C327186AF4E23C"
        "1A946834B6150BDA2583E9CA2AD44CE8"
        "DBBBC2DB04DE8EF92E8EFC141FBECAA6"
        "287C59474E6BC05D99B2964FA090C3A2"
        "233BA186515BE7ED1F612970CEE2D7AF"
        "B81BDD762170481CD0069127D5B05AA9"
        "93B4EA988D8FDDC186FFB7DC90A6C08F"
        "4DF435C934063199FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_4096_prime");

    if (wolfSSL_BN_hex2bn(&bn, prm) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error converting DH 4096 prime to big number");
        return NULL;
    }

    return bn;
}

/* This sets a big number with the 6144-bit prime from RFC 3526.
 *
 * bn  if not NULL then the big number structure is used. If NULL then a new
 *     big number structure is created.
 *
 * Returns a WOLFSSL_BIGNUM structure on success and NULL with failure.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_6144_prime(WOLFSSL_BIGNUM* bn)
{
    const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28F"
        "B5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33"
        "A85521ABDF1CBA64ECFB850458DBEF0A"
        "8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619D"
        "CEE3D2261AD2EE6BF12FFA06D98A0864"
        "D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E2"
        "08E24FA074E5AB3143DB5BFCE0FD108E"
        "4B82D120A92108011A723C12A787E6D7"
        "88719A10BDBA5B2699C327186AF4E23C"
        "1A946834B6150BDA2583E9CA2AD44CE8"
        "DBBBC2DB04DE8EF92E8EFC141FBECAA6"
        "287C59474E6BC05D99B2964FA090C3A2"
        "233BA186515BE7ED1F612970CEE2D7AF"
        "B81BDD762170481CD0069127D5B05AA9"
        "93B4EA988D8FDDC186FFB7DC90A6C08F"
        "4DF435C93402849236C3FAB4D27C7026"
        "C1D4DCB2602646DEC9751E763DBA37BD"
        "F8FF9406AD9E530EE5DB382F413001AE"
        "B06A53ED9027D831179727B0865A8918"
        "DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
        "DB7F1447E6CC254B332051512BD7AF42"
        "6FB8F401378CD2BF5983CA01C64B92EC"
        "F032EA15D1721D03F482D7CE6E74FEF6"
        "D55E702F46980C82B5A84031900B1C9E"
        "59E7C97FBEC7E8F323A97A7E36CC88BE"
        "0F1D45B7FF585AC54BD407B22B4154AA"
        "CC8F6D7EBF48E1D814CC5ED20F8037E0"
        "A79715EEF29BE32806A1D58BB7C5DA76"
        "F550AA3D8A1FBFF0EB19CCB1A313D55C"
        "DA56C9EC2EF29632387FE8D76E3C0468"
        "043E8F663F4860EE12BF2D5B0B7474D6"
        "E694F91E6DCC4024FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_6144_prime");

    if (wolfSSL_BN_hex2bn(&bn, prm) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error converting DH 6144 prime to big number");
        return NULL;
    }

    return bn;
}


/* This sets a big number with the 8192-bit prime from RFC 3526.
 *
 * bn  if not NULL then the big number structure is used. If NULL then a new
 *     big number structure is created.
 *
 * Returns a WOLFSSL_BIGNUM structure on success and NULL with failure.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_8192_prime(WOLFSSL_BIGNUM* bn)
{
    const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28F"
        "B5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33"
        "A85521ABDF1CBA64ECFB850458DBEF0A"
        "8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619D"
        "CEE3D2261AD2EE6BF12FFA06D98A0864"
        "D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E2"
        "08E24FA074E5AB3143DB5BFCE0FD108E"
        "4B82D120A92108011A723C12A787E6D7"
        "88719A10BDBA5B2699C327186AF4E23C"
        "1A946834B6150BDA2583E9CA2AD44CE8"
        "DBBBC2DB04DE8EF92E8EFC141FBECAA6"
        "287C59474E6BC05D99B2964FA090C3A2"
        "233BA186515BE7ED1F612970CEE2D7AF"
        "B81BDD762170481CD0069127D5B05AA9"
        "93B4EA988D8FDDC186FFB7DC90A6C08F"
        "4DF435C93402849236C3FAB4D27C7026"
        "C1D4DCB2602646DEC9751E763DBA37BD"
        "F8FF9406AD9E530EE5DB382F413001AE"
        "B06A53ED9027D831179727B0865A8918"
        "DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
        "DB7F1447E6CC254B332051512BD7AF42"
        "6FB8F401378CD2BF5983CA01C64B92EC"
        "F032EA15D1721D03F482D7CE6E74FEF6"
        "D55E702F46980C82B5A84031900B1C9E"
        "59E7C97FBEC7E8F323A97A7E36CC88BE"
        "0F1D45B7FF585AC54BD407B22B4154AA"
        "CC8F6D7EBF48E1D814CC5ED20F8037E0"
        "A79715EEF29BE32806A1D58BB7C5DA76"
        "F550AA3D8A1FBFF0EB19CCB1A313D55C"
        "DA56C9EC2EF29632387FE8D76E3C0468"
        "043E8F663F4860EE12BF2D5B0B7474D6"
        "E694F91E6DBE115974A3926F12FEE5E4"
        "38777CB6A932DF8CD8BEC4D073B931BA"
        "3BC832B68D9DD300741FA7BF8AFC47ED"
        "2576F6936BA424663AAB639C5AE4F568"
        "3423B4742BF1C978238F16CBE39D652D"
        "E3FDB8BEFC848AD922222E04A4037C07"
        "13EB57A81A23F0C73473FC646CEA306B"
        "4BCBC8862F8385DDFA9D4B7FA2C087E8"
        "79683303ED5BDD3A062B3CF5B3A278A6"
        "6D2A13F83F44F82DDF310EE074AB6A36"
        "4597E899A0255DC164F31CC50846851D"
        "F9AB48195DED7EA1B1D510BD7EE74D73"
        "FAF36BC31ECFA268359046F4EB879F92"
        "4009438B481C6CD7889A002ED5EE382B"
        "C9190DA6FC026E479558E4475677E9AA"
        "9E3050E2765694DFC81F56E880B96E71"
        "60C980DD98EDD3DFFFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_8192_prime");

    if (wolfSSL_BN_hex2bn(&bn, prm) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error converting DH 8192 prime to big number");
        return NULL;
    }

    return bn;
}

/* The functions inside the macro guard below are fine to use with FIPS provided
 * WOLFSSL_DH_EXTRA isn't defined. That define will cause SetDhInternal to have
 * a call to wc_DhImportKeyPair, which isn't defined in the FIPS v2 module. */
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS) && !defined(WOLFSSL_DH_EXTRA)) \
 || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_DH_generate_key(WOLFSSL_DH* dh)
{
    int            ret    = WOLFSSL_FAILURE;
    word32         pubSz  = 0;
    word32         privSz = 0;
    int            initTmpRng = 0;
    WC_RNG*        rng    = NULL;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG*        tmpRNG;
#else
    WC_RNG         tmpRNG[1];
#endif
    unsigned char* pub    = NULL;
    unsigned char* priv   = NULL;

    WOLFSSL_MSG("wolfSSL_DH_generate_key");

#ifdef WOLFSSL_SMALL_STACK
    tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
    if (tmpRNG == NULL) {
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
        return ret;
    }
#endif

    if (dh == NULL || dh->p == NULL || dh->g == NULL)
        WOLFSSL_MSG("Bad function arguments");
    else if (dh->inSet == 0 && SetDhInternal(dh) != WOLFSSL_SUCCESS)
            WOLFSSL_MSG("Bad DH set internal");
    else if (wc_InitRng(tmpRNG) == 0) {
        rng = tmpRNG;
        initTmpRng = 1;
    }
    else {
        WOLFSSL_MSG("Bad RNG Init, trying global");
        rng = wolfssl_get_global_rng();
    }

    if (rng) {
        pubSz = wolfSSL_BN_num_bytes(dh->p);
        if (dh->length) {
            privSz = dh->length/8; /* to bytes */
        } else {
            privSz = pubSz;
        }
        if (pubSz > 0) {
            pub = (unsigned char*)XMALLOC(pubSz,
                    NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        }
        if (privSz > 0) {
            priv = (unsigned char*)XMALLOC(privSz,
                    NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        }
        PRIVATE_KEY_UNLOCK();
        if (pub == NULL || priv == NULL) {
            WOLFSSL_MSG("Unable to malloc memory");
        }
        else if (wc_DhGenerateKeyPair((DhKey*)dh->internal, rng, priv, &privSz,
                                                               pub, &pubSz) < 0)
            WOLFSSL_MSG("Bad wc_DhGenerateKeyPair");
        else {
            if (dh->pub_key)
                wolfSSL_BN_free(dh->pub_key);

            dh->pub_key = wolfSSL_BN_new();
            if (dh->pub_key == NULL) {
                WOLFSSL_MSG("Bad DH new pub");
            }
            if (dh->priv_key)
                wolfSSL_BN_free(dh->priv_key);

            dh->priv_key = wolfSSL_BN_new();

            if (dh->priv_key == NULL) {
                WOLFSSL_MSG("Bad DH new priv");
            }

            if (dh->pub_key && dh->priv_key) {
               if (wolfSSL_BN_bin2bn(pub, pubSz, dh->pub_key) == NULL)
                   WOLFSSL_MSG("Bad DH bn2bin error pub");
               else if (wolfSSL_BN_bin2bn(priv, privSz, dh->priv_key) == NULL)
                   WOLFSSL_MSG("Bad DH bn2bin error priv");
               else
                   ret = WOLFSSL_SUCCESS;
            }
        }
        PRIVATE_KEY_LOCK();
    }

    if (initTmpRng)
        wc_FreeRng(tmpRNG);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
#endif
    XFREE(pub,    NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(priv,   NULL, DYNAMIC_TYPE_PRIVATE_KEY);

    return ret;
}


/* return code compliant with OpenSSL :
 *   size of shared secret if success, -1 if error
 */
int wolfSSL_DH_compute_key(unsigned char* key, const WOLFSSL_BIGNUM* otherPub,
                          WOLFSSL_DH* dh)
{
    int            ret    = WOLFSSL_FATAL_ERROR;
    word32         keySz  = 0;
    int            pubSz  = 1024;
    int            privSz = 1024;
#ifdef WOLFSSL_SMALL_STACK
    unsigned char* pub;
    unsigned char* priv   = NULL;
#else
    unsigned char  pub [1024];
    unsigned char  priv[1024];
#endif

    WOLFSSL_MSG("wolfSSL_DH_compute_key");

#ifdef WOLFSSL_SMALL_STACK
    pub = (unsigned char*)XMALLOC(pubSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    if (pub == NULL)
        return ret;

    priv = (unsigned char*)XMALLOC(privSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
    if (priv == NULL) {
        XFREE(pub, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        return ret;
    }
#endif

    if (dh == NULL || dh->priv_key == NULL || otherPub == NULL)
        WOLFSSL_MSG("Bad function arguments");
    else if ((keySz = (word32)DH_size(dh)) == 0)
        WOLFSSL_MSG("Bad DH_size");
    else if (wolfSSL_BN_bn2bin(dh->priv_key, NULL) > (int)privSz)
        WOLFSSL_MSG("Bad priv internal size");
    else if (wolfSSL_BN_bn2bin(otherPub, NULL) > (int)pubSz)
        WOLFSSL_MSG("Bad otherPub size");
    else {
        privSz = wolfSSL_BN_bn2bin(dh->priv_key, priv);
        pubSz  = wolfSSL_BN_bn2bin(otherPub, pub);
        if (dh->inSet == 0 && SetDhInternal(dh) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Bad DH set internal");
        }
        PRIVATE_KEY_UNLOCK();
        if (privSz <= 0 || pubSz <= 0)
            WOLFSSL_MSG("Bad BN2bin set");
        else if (wc_DhAgree((DhKey*)dh->internal, key, &keySz,
                            priv, privSz, pub, pubSz) < 0)
            WOLFSSL_MSG("wc_DhAgree failed");
        else
            ret = (int)keySz;
        PRIVATE_KEY_LOCK();
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(pub,  NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(priv, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
#endif

    WOLFSSL_LEAVE("wolfSSL_DH_compute_key", ret);

    return ret;
}


#if defined(OPENSSL_ALL) || \
    defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
int wolfSSL_DH_set_length(WOLFSSL_DH *dh, long len)
{
    WOLFSSL_ENTER("wolfSSL_DH_set_length");

    /* len is checked at generation */
    if (dh == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    dh->length = (int)len;
    return WOLFSSL_SUCCESS;
}

/* ownership of p,q,and g get taken over by "dh" on success and should be free'd
 * with a call to wolfSSL_DH_free -- not individually.
 *
 * returns WOLFSSL_SUCCESS on success
 */
int wolfSSL_DH_set0_pqg(WOLFSSL_DH *dh, WOLFSSL_BIGNUM *p,
    WOLFSSL_BIGNUM *q, WOLFSSL_BIGNUM *g)
{
    int ret;
    WOLFSSL_ENTER("wolfSSL_DH_set0_pqg");

    /* q can be NULL */
    if (dh == NULL || p == NULL || g == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    /* free existing internal DH structure and recreate with new p / g */
    if (dh->inSet) {
#ifndef HAVE_SELFTEST
        ret = wc_FreeDhKey((DhKey*)dh->internal);
        if (ret != 0) {
            WOLFSSL_MSG("Unable to free internal DH key");
            return WOLFSSL_FAILURE;
        }
#else
        /* Selftest code has this API with a void return type */
        wc_FreeDhKey((DhKey*)dh->internal);
#endif
    }

    wolfSSL_BN_free(dh->p);
    wolfSSL_BN_free(dh->q);
    wolfSSL_BN_free(dh->g);

    dh->p = p;
    dh->q = q;
    dh->g = g;

    ret = SetDhInternal(dh);
    if (ret != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Unable to set internal DH key");
        dh->p = NULL;
        dh->q = NULL;
        dh->g = NULL;
        dh->inSet = 0;
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* OPENSSL_ALL || (v1.1.0 or later) */
#endif /* !HAVE_FIPS || (HAVE_FIPS && !WOLFSSL_DH_EXTRA) ||
        * HAVE_FIPS_VERSION > 2 */

void wolfSSL_DH_get0_key(const WOLFSSL_DH *dh,
        const WOLFSSL_BIGNUM **pub_key, const WOLFSSL_BIGNUM **priv_key)
{
    WOLFSSL_ENTER("wolfSSL_DH_get0_key");

    if (dh != NULL) {
        if (pub_key != NULL && dh->pub_key != NULL &&
                wolfSSL_BN_is_zero(dh->pub_key) != WOLFSSL_SUCCESS)
            *pub_key = dh->pub_key;
        if (priv_key != NULL && dh->priv_key != NULL &&
                wolfSSL_BN_is_zero(dh->priv_key) != WOLFSSL_SUCCESS)
            *priv_key = dh->priv_key;
    }
}

int wolfSSL_DH_set0_key(WOLFSSL_DH *dh, WOLFSSL_BIGNUM *pub_key,
        WOLFSSL_BIGNUM *priv_key)
{
    WOLFSSL_ENTER("wolfSSL_DH_set0_key");

    if (dh == NULL)
        return WOLFSSL_FAILURE;

    if (pub_key != NULL) {
        wolfSSL_BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }

    if (priv_key != NULL) {
        wolfSSL_BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    if (dh->p == NULL || dh->g == NULL)
        return WOLFSSL_SUCCESS; /* Allow loading parameters afterwards */
    else
        return SetDhInternal(dh);
}

/* See RFC 5114 section 2.3, "2048-bit MODP Group with 256-bit Prime Order
 * Subgroup." */
WOLFSSL_DH* wolfSSL_DH_get_2048_256(void)
{
    WOLFSSL_DH* ret;
    int err = 0;
    const byte pHex[] = {
        0x87, 0xA8, 0xE6, 0x1D, 0xB4, 0xB6, 0x66, 0x3C, 0xFF, 0xBB, 0xD1, 0x9C,
        0x65, 0x19, 0x59, 0x99, 0x8C, 0xEE, 0xF6, 0x08, 0x66, 0x0D, 0xD0, 0xF2,
        0x5D, 0x2C, 0xEE, 0xD4, 0x43, 0x5E, 0x3B, 0x00, 0xE0, 0x0D, 0xF8, 0xF1,
        0xD6, 0x19, 0x57, 0xD4, 0xFA, 0xF7, 0xDF, 0x45, 0x61, 0xB2, 0xAA, 0x30,
        0x16, 0xC3, 0xD9, 0x11, 0x34, 0x09, 0x6F, 0xAA, 0x3B, 0xF4, 0x29, 0x6D,
        0x83, 0x0E, 0x9A, 0x7C, 0x20, 0x9E, 0x0C, 0x64, 0x97, 0x51, 0x7A, 0xBD,
        0x5A, 0x8A, 0x9D, 0x30, 0x6B, 0xCF, 0x67, 0xED, 0x91, 0xF9, 0xE6, 0x72,
        0x5B, 0x47, 0x58, 0xC0, 0x22, 0xE0, 0xB1, 0xEF, 0x42, 0x75, 0xBF, 0x7B,
        0x6C, 0x5B, 0xFC, 0x11, 0xD4, 0x5F, 0x90, 0x88, 0xB9, 0x41, 0xF5, 0x4E,
        0xB1, 0xE5, 0x9B, 0xB8, 0xBC, 0x39, 0xA0, 0xBF, 0x12, 0x30, 0x7F, 0x5C,
        0x4F, 0xDB, 0x70, 0xC5, 0x81, 0xB2, 0x3F, 0x76, 0xB6, 0x3A, 0xCA, 0xE1,
        0xCA, 0xA6, 0xB7, 0x90, 0x2D, 0x52, 0x52, 0x67, 0x35, 0x48, 0x8A, 0x0E,
        0xF1, 0x3C, 0x6D, 0x9A, 0x51, 0xBF, 0xA4, 0xAB, 0x3A, 0xD8, 0x34, 0x77,
        0x96, 0x52, 0x4D, 0x8E, 0xF6, 0xA1, 0x67, 0xB5, 0xA4, 0x18, 0x25, 0xD9,
        0x67, 0xE1, 0x44, 0xE5, 0x14, 0x05, 0x64, 0x25, 0x1C, 0xCA, 0xCB, 0x83,
        0xE6, 0xB4, 0x86, 0xF6, 0xB3, 0xCA, 0x3F, 0x79, 0x71, 0x50, 0x60, 0x26,
        0xC0, 0xB8, 0x57, 0xF6, 0x89, 0x96, 0x28, 0x56, 0xDE, 0xD4, 0x01, 0x0A,
        0xBD, 0x0B, 0xE6, 0x21, 0xC3, 0xA3, 0x96, 0x0A, 0x54, 0xE7, 0x10, 0xC3,
        0x75, 0xF2, 0x63, 0x75, 0xD7, 0x01, 0x41, 0x03, 0xA4, 0xB5, 0x43, 0x30,
        0xC1, 0x98, 0xAF, 0x12, 0x61, 0x16, 0xD2, 0x27, 0x6E, 0x11, 0x71, 0x5F,
        0x69, 0x38, 0x77, 0xFA, 0xD7, 0xEF, 0x09, 0xCA, 0xDB, 0x09, 0x4A, 0xE9,
        0x1E, 0x1A, 0x15, 0x97
   };
    const byte gHex[] = {
        0x3F, 0xB3, 0x2C, 0x9B, 0x73, 0x13, 0x4D, 0x0B, 0x2E, 0x77, 0x50, 0x66,
        0x60, 0xED, 0xBD, 0x48, 0x4C, 0xA7, 0xB1, 0x8F, 0x21, 0xEF, 0x20, 0x54,
        0x07, 0xF4, 0x79, 0x3A, 0x1A, 0x0B, 0xA1, 0x25, 0x10, 0xDB, 0xC1, 0x50,
        0x77, 0xBE, 0x46, 0x3F, 0xFF, 0x4F, 0xED, 0x4A, 0xAC, 0x0B, 0xB5, 0x55,
        0xBE, 0x3A, 0x6C, 0x1B, 0x0C, 0x6B, 0x47, 0xB1, 0xBC, 0x37, 0x73, 0xBF,
        0x7E, 0x8C, 0x6F, 0x62, 0x90, 0x12, 0x28, 0xF8, 0xC2, 0x8C, 0xBB, 0x18,
        0xA5, 0x5A, 0xE3, 0x13, 0x41, 0x00, 0x0A, 0x65, 0x01, 0x96, 0xF9, 0x31,
        0xC7, 0x7A, 0x57, 0xF2, 0xDD, 0xF4, 0x63, 0xE5, 0xE9, 0xEC, 0x14, 0x4B,
        0x77, 0x7D, 0xE6, 0x2A, 0xAA, 0xB8, 0xA8, 0x62, 0x8A, 0xC3, 0x76, 0xD2,
        0x82, 0xD6, 0xED, 0x38, 0x64, 0xE6, 0x79, 0x82, 0x42, 0x8E, 0xBC, 0x83,
        0x1D, 0x14, 0x34, 0x8F, 0x6F, 0x2F, 0x91, 0x93, 0xB5, 0x04, 0x5A, 0xF2,
        0x76, 0x71, 0x64, 0xE1, 0xDF, 0xC9, 0x67, 0xC1, 0xFB, 0x3F, 0x2E, 0x55,
        0xA4, 0xBD, 0x1B, 0xFF, 0xE8, 0x3B, 0x9C, 0x80, 0xD0, 0x52, 0xB9, 0x85,
        0xD1, 0x82, 0xEA, 0x0A, 0xDB, 0x2A, 0x3B, 0x73, 0x13, 0xD3, 0xFE, 0x14,
        0xC8, 0x48, 0x4B, 0x1E, 0x05, 0x25, 0x88, 0xB9, 0xB7, 0xD2, 0xBB, 0xD2,
        0xDF, 0x01, 0x61, 0x99, 0xEC, 0xD0, 0x6E, 0x15, 0x57, 0xCD, 0x09, 0x15,
        0xB3, 0x35, 0x3B, 0xBB, 0x64, 0xE0, 0xEC, 0x37, 0x7F, 0xD0, 0x28, 0x37,
        0x0D, 0xF9, 0x2B, 0x52, 0xC7, 0x89, 0x14, 0x28, 0xCD, 0xC6, 0x7E, 0xB6,
        0x18, 0x4B, 0x52, 0x3D, 0x1D, 0xB2, 0x46, 0xC3, 0x2F, 0x63, 0x07, 0x84,
        0x90, 0xF0, 0x0E, 0xF8, 0xD6, 0x47, 0xD1, 0x48, 0xD4, 0x79, 0x54, 0x51,
        0x5E, 0x23, 0x27, 0xCF, 0xEF, 0x98, 0xC5, 0x82, 0x66, 0x4B, 0x4C, 0x0F,
        0x6C, 0xC4, 0x16, 0x59
    };
    const byte qHex[] = {
        0x8C, 0xF8, 0x36, 0x42, 0xA7, 0x09, 0xA0, 0x97, 0xB4, 0x47, 0x99, 0x76,
        0x40, 0x12, 0x9D, 0xA2, 0x99, 0xB1, 0xA4, 0x7D, 0x1E, 0xB3, 0x75, 0x0B,
        0xA3, 0x08, 0xB0, 0xFE, 0x64, 0xF5, 0xFB, 0xD3
    };
    WOLFSSL_BIGNUM* pBn = NULL;
    WOLFSSL_BIGNUM* gBn = NULL;
    WOLFSSL_BIGNUM* qBn = NULL;

    ret = wolfSSL_DH_new();
    if (ret == NULL) {
        err = 1;
    }
    if (err == 0) {
        pBn = wolfSSL_BN_bin2bn(pHex, (int)sizeof(pHex), NULL);
        if (pBn == NULL) {
            WOLFSSL_MSG("Error converting p hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
    if (err == 0) {
        gBn = wolfSSL_BN_bin2bn(gHex, (int)sizeof(gHex), NULL);
        if (gBn == NULL) {
            WOLFSSL_MSG("Error converting g hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
    if (err == 0) {
        qBn = wolfSSL_BN_bin2bn(qHex, (int)sizeof(qHex), NULL);
        if (qBn == NULL) {
            WOLFSSL_MSG("Error converting q hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
    if (err == 0) {
    #if defined(OPENSSL_ALL) || \
        defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
        if (wolfSSL_DH_set0_pqg(ret, pBn, qBn, gBn) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Error setting DH parameters.");
            err = 1;
        }
    #else
        ret->p = pBn;
        ret->q = qBn;
        ret->g = gBn;

        if (SetDhInternal(ret) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Error setting DH parameters.");
            err = 1;
        }
    #endif
    }

    if (err == 1) {
        wolfSSL_BN_free(pBn);
        wolfSSL_BN_free(gBn);
        wolfSSL_BN_free(qBn);
        wolfSSL_DH_free(ret);
        ret = NULL;
    }

    return ret;
}

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || \
    defined(WOLFSSL_OPENSSH) || defined(OPENSSL_EXTRA)
/* return WOLFSSL_SUCCESS if success, WOLFSSL_FATAL_ERROR if error */
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
int wolfSSL_DH_LoadDer(WOLFSSL_DH* dh, const unsigned char* derBuf, int derSz)
{
    word32 idx = 0;
    int    ret;

    if (dh == NULL || dh->internal == NULL || derBuf == NULL || derSz <= 0) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    ret = wc_DhKeyDecode(derBuf, &idx, (DhKey*)dh->internal, (word32)derSz);
    if (ret < 0) {
        WOLFSSL_MSG("wc_DhKeyDecode failed");
        return WOLFSSL_FATAL_ERROR;
    }
    dh->inSet = 1;

    if (SetDhExternal(dh) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetDhExternal failed");
        return WOLFSSL_FATAL_ERROR;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* WOLFSSL_QT || OPENSSL_ALL || WOLFSSL_OPENSSH || OPENSSL_EXTRA */

#endif /* OPENSSL_EXTRA */

#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL) \
    || defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(OPENSSL_EXTRA)

#ifndef NO_BIO
WOLFSSL_DH *wolfSSL_PEM_read_bio_DHparams(WOLFSSL_BIO *bio, WOLFSSL_DH **x,
        wc_pem_password_cb *cb, void *u)
{
#ifndef NO_FILESYSTEM
    WOLFSSL_DH* localDh = NULL;
    unsigned char* mem  = NULL;
    word32 size;
    long   sz;
    int    ret;
    DerBuffer *der = NULL;
    byte*  p = NULL;
    byte*  g = NULL;
    word32 pSz = MAX_DH_SIZE;
    word32 gSz = MAX_DH_SIZE;
    int    memAlloced = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_DHparams");
    (void)cb;
    (void)u;

    if (bio == NULL) {
        WOLFSSL_MSG("Bad Function Argument bio is NULL");
        return NULL;
    }

    if (bio->type == WOLFSSL_BIO_MEMORY) {
        /* Use the buffer directly. */
        ret = wolfSSL_BIO_get_mem_data(bio, &mem);
        if (mem == NULL || ret <= 0) {
            WOLFSSL_MSG("Failed to get data from bio struct");
            goto end;
        }
        size = ret;
    }
    else if (bio->type == WOLFSSL_BIO_FILE) {
        /* Read whole file into a new buffer. */
        if (XFSEEK((XFILE)bio->ptr, 0, SEEK_END) != 0)
            goto end;
        sz = XFTELL((XFILE)bio->ptr);
        if (XFSEEK((XFILE)bio->ptr, 0, SEEK_SET) != 0)
            goto end;
        if (sz > MAX_WOLFSSL_FILE_SIZE || sz <= 0L) {
            WOLFSSL_MSG("PEM_read_bio_DHparams file size error");
            goto end;
        }
        mem = (unsigned char*)XMALLOC(sz, NULL, DYNAMIC_TYPE_PEM);
        if (mem == NULL)
            goto end;
        memAlloced = 1;

        if (wolfSSL_BIO_read(bio, (char *)mem, (int)sz) <= 0)
            goto end;
        size = (word32)sz;
    }
    else {
        WOLFSSL_MSG("BIO type not supported for reading DH parameters");
        goto end;
    }

    ret = PemToDer(mem, size, DH_PARAM_TYPE, &der, NULL, NULL, NULL);
    if (ret < 0) {
        /* Also try X9.42 format */
        ret = PemToDer(mem, size, X942_PARAM_TYPE, &der, NULL, NULL, NULL);
    }
    if (ret != 0)
        goto end;

    /* Use the object passed in, otherwise allocate a new object */
    if (x != NULL)
        localDh = *x;
    if (localDh == NULL) {
        localDh = wolfSSL_DH_new();
        if (localDh == NULL)
            goto end;
    }

    /* Load data in manually */
    p = (byte*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    g = (byte*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    if (p == NULL || g == NULL)
        goto end;
    /* Extract the p and g as data from the DER encoded DH parameters. */
    ret = wc_DhParamsLoad(der->buffer, der->length, p, &pSz, g, &gSz);
    if (ret != 0) {
        if (x != NULL && localDh != *x)
            XFREE(localDh, NULL, DYNAMIC_TYPE_OPENSSL);
        localDh = NULL;
        goto end;
    }

    if (x != NULL)
        *x = localDh;

    /* Put p and g in as big numbers. */
    if (localDh->p != NULL) {
        wolfSSL_BN_free(localDh->p);
        localDh->p = NULL;
    }
    if (localDh->g != NULL) {
        wolfSSL_BN_free(localDh->g);
        localDh->g = NULL;
    }
    localDh->p = wolfSSL_BN_bin2bn(p, pSz, NULL);
    localDh->g = wolfSSL_BN_bin2bn(g, gSz, NULL);
    if (localDh->p == NULL || localDh->g == NULL) {
        if (x != NULL && localDh != *x)
            wolfSSL_DH_free(localDh);
        localDh = NULL;
    }

    if (localDh != NULL && localDh->inSet == 0) {
        if (SetDhInternal(localDh) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Unable to set internal DH structure");
            wolfSSL_DH_free(localDh);
            localDh = NULL;
        }
    }

end:
    if (memAlloced) XFREE(mem, NULL, DYNAMIC_TYPE_PEM);
    if (der != NULL) FreeDer(&der);
    XFREE(p, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(g, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    return localDh;
#else
    (void)bio;
    (void)x;
    (void)cb;
    (void)u;
    return NULL;
#endif
}

#ifndef NO_FILESYSTEM
/* Reads DH parameters from a file pointer into WOLFSSL_DH structure.
 *
 * fp  file pointer to read DH parameter file from
 * x   output WOLFSSL_DH to be created and populated from fp
 * cb  password callback, to be used to decrypt encrypted DH parameters PEM
 * u   context pointer to user-defined data to be received back in password cb
 *
 * Returns new WOLFSSL_DH structure pointer on success, NULL on failure. */
WOLFSSL_DH *wolfSSL_PEM_read_DHparams(XFILE fp, WOLFSSL_DH **x,
        wc_pem_password_cb *cb, void *u)
{
    WOLFSSL_BIO* fbio = NULL;
    WOLFSSL_DH* dh = NULL;

    if (fp == NULL) {
        WOLFSSL_MSG("DH parameter file cannot be NULL");
        return NULL;
    }

    fbio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    if (fbio == NULL) {
        WOLFSSL_MSG("Unable to create file BIO to process DH PEM");
        return NULL;
    }

    if (wolfSSL_BIO_set_fp(fbio, fp, BIO_NOCLOSE) != WOLFSSL_SUCCESS) {
        wolfSSL_BIO_free(fbio);
        WOLFSSL_MSG("wolfSSL_BIO_set_fp error");
        return NULL;
    }

    /* wolfSSL_PEM_read_bio_DHparams() sanitizes x, cb, u args */
    dh = wolfSSL_PEM_read_bio_DHparams(fbio, x, cb, u);
    wolfSSL_BIO_free(fbio);
    return dh;
}
#endif /* !NO_FILESYSTEM */

#endif /* !NO_BIO */

#if defined(WOLFSSL_DH_EXTRA) && !defined(NO_FILESYSTEM)
/* Writes the DH parameters in PEM format from "dh" out to the file pointer
 * passed in.
 *
 * returns WOLFSSL_SUCCESS on success
 */
int wolfSSL_PEM_write_DHparams(XFILE fp, WOLFSSL_DH* dh)
{
    int ret;
    word32 derSz = 0, pemSz = 0;
    byte *der, *pem;
    DhKey* key;

    WOLFSSL_ENTER("wolfSSL_PEM_write_DHparams");

    if (dh == NULL) {
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", BAD_FUNC_ARG);
        return WOLFSSL_FAILURE;
    }

    if (dh->inSet == 0) {
        if (SetDhInternal(dh) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Unable to set internal DH structure");
            return WOLFSSL_FAILURE;
        }
    }
    key = (DhKey*)dh->internal;
    ret = wc_DhParamsToDer(key, NULL, &derSz);
    if (ret != LENGTH_ONLY_E) {
        WOLFSSL_MSG("Failed to get size of DH params");
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);
        return WOLFSSL_FAILURE;
    }

    der = (byte*)XMALLOC(derSz, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL) {
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", MEMORY_E);
        return WOLFSSL_FAILURE;
    }
    ret = wc_DhParamsToDer(key, der, &derSz);
    if (ret <= 0) {
        WOLFSSL_MSG("Failed to export DH params");
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);
        XFREE(der, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FAILURE;
    }

    /* convert to PEM */
    ret = wc_DerToPem(der, derSz, NULL, 0, DH_PARAM_TYPE);
    if (ret < 0) {
        WOLFSSL_MSG("Failed to convert DH params to PEM");
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);
        XFREE(der, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    pemSz = (word32)ret;

    pem = (byte*)XMALLOC(pemSz, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", MEMORY_E);
        XFREE(der, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    ret = wc_DerToPem(der, derSz, pem, pemSz, DH_PARAM_TYPE);
    XFREE(der, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret < 0) {
        WOLFSSL_MSG("Failed to convert DH params to PEM");
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);
        XFREE(pem, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ret = (int)XFWRITE(pem, 1, pemSz, fp);
    XFREE(pem, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret <= 0) {
        WOLFSSL_MSG("Failed to write to file");
        WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);
        return WOLFSSL_FAILURE;
    }
    WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}
#endif /* WOLFSSL_DH_EXTRA && !NO_FILESYSTEM */

#endif /* HAVE_LIGHTY || HAVE_STUNNEL || WOLFSSL_MYSQL_COMPATIBLE ||
        * OPENSSL_EXTRA */

#if defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
    defined(WOLFSSL_OPENSSH) || defined(HAVE_SBLIM_SFCB)))

#if defined(WOLFSSL_KEY_GEN) && !defined(HAVE_SELFTEST)
WOLFSSL_DH *wolfSSL_DH_generate_parameters(int prime_len, int generator,
                           void (*callback) (int, int, void *), void *cb_arg)
{
    WOLFSSL_DH* dh;

    WOLFSSL_ENTER("wolfSSL_DH_generate_parameters");
    (void)callback;
    (void)cb_arg;

    if ((dh = wolfSSL_DH_new()) == NULL) {
        WOLFSSL_MSG("wolfSSL_DH_new error");
        return NULL;
    }

    if (wolfSSL_DH_generate_parameters_ex(dh, prime_len, generator, NULL)
            != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_DH_generate_parameters_ex error");
        wolfSSL_DH_free(dh);
        return NULL;
    }

    return dh;
}

int wolfSSL_DH_generate_parameters_ex(WOLFSSL_DH* dh, int prime_len,
    int generator, void (*callback) (int, int, void *))
{
    DhKey* key;
    WC_RNG* rng;

    WOLFSSL_ENTER("wolfSSL_DH_generate_parameters_ex");
    (void)callback;
    (void)generator;

    if (dh == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    if ((rng = wolfssl_get_global_rng()) == NULL) {
        if (wolfSSL_RAND_Init() != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("No RNG to use");
            return WOLFSSL_FAILURE;
        }
        rng = wolfssl_get_global_rng();
    }

    /* Don't need SetDhInternal call since we are generating
     * parameters ourselves */

    key = (DhKey*)dh->internal;

    /* Free so that mp_init's don't leak */
    wc_FreeDhKey(key);

    if (wc_DhGenerateParams(rng, prime_len, key) != 0) {
        WOLFSSL_MSG("wc_DhGenerateParams error");
        return WOLFSSL_FAILURE;
    }
    dh->inSet = 1;

    WOLFSSL_MSG("wolfSSL does not support using a custom generator.");

    if (SetDhExternal(dh) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetDhExternal error");
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* WOLFSSL_KEY_GEN && !HAVE_SELFTEST */

#endif /* OPENSSL_ALL || (OPENSSL_EXTRA && (HAVE_STUNNEL || WOLFSSL_NGINX ||
        * HAVE_LIGHTY || WOLFSSL_HAPROXY || WOLFSSL_OPENSSH ||
        * HAVE_SBLIM_SFCB)) */

#ifdef OPENSSL_EXTRA

/**
 * Return DH p, q and g parameters
 * @param dh a pointer to WOLFSSL_DH
 * @param p  a pointer to WOLFSSL_BIGNUM to be obtained from dh
 * @param q  a pointer to WOLFSSL_BIGNUM to be obtained from dh
 * @param g  a pointer to WOLFSSL_BIGNUM to be obtained from dh
 */
void wolfSSL_DH_get0_pqg(const WOLFSSL_DH *dh, const WOLFSSL_BIGNUM **p,
                    const WOLFSSL_BIGNUM **q, const WOLFSSL_BIGNUM **g)
{
    WOLFSSL_ENTER("wolfSSL_DH_get0_pqg");
    if (dh == NULL)
        return;

    if (p != NULL)
        *p = dh->p;
    if (q != NULL)
        *q = dh->q;
    if (g != NULL)
        *g = dh->g;
}

#endif /* OPENSSL_EXTRA */

#endif /* NO_DH */

/*******************************************************************************
 * END OF DH API
 ******************************************************************************/


/*******************************************************************************
 * START OF EC API
 ******************************************************************************/

#ifdef HAVE_ECC

#ifdef OPENSSL_EXTRA

#ifndef NO_CERTS

#if defined(XFPRINTF) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM)
int wolfSSL_EC_KEY_print_fp(XFILE fp, WOLFSSL_EC_KEY* key, int indent)
{
    int ret = WOLFSSL_SUCCESS;
    int bits = 0;
    int priv = 0;
    int nid = 0;
    const char* curve;
    const char* nistName;
    WOLFSSL_BIGNUM* pubBn = NULL;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_print_fp");

    if (fp == XBADFILE || key == NULL || key->group == NULL || indent < 0) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        bits = wolfSSL_EC_GROUP_order_bits(key->group);
        if (bits <= 0) {
            WOLFSSL_MSG("Failed to get group order bits.");
            ret = WOLFSSL_FAILURE;
        }
    }
    if (ret == WOLFSSL_SUCCESS) {
        XFPRINTF(fp, "%*s", indent, "");
        if (key->priv_key != NULL && !wolfSSL_BN_is_zero(key->priv_key)) {
            XFPRINTF(fp, "Private-Key: (%d bit)\n", bits);
            priv = 1;
        }
        else {
            XFPRINTF(fp, "Public-Key: (%d bit)\n", bits);
        }

        if (priv) {
            ret = PrintBNFieldFp(fp, indent, "priv", key->priv_key);
        }
    }
    if (ret == WOLFSSL_SUCCESS && key->pub_key != NULL && key->pub_key->exSet) {
        pubBn = wolfSSL_EC_POINT_point2bn(key->group, key->pub_key,
                                          POINT_CONVERSION_UNCOMPRESSED, NULL,
                                          NULL);
        if (pubBn == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_POINT_point2bn failed.");
            ret = WOLFSSL_FAILURE;
        }
        else {
            ret = PrintBNFieldFp(fp, indent, "pub", pubBn);
        }
    }
    if (ret == WOLFSSL_SUCCESS) {
        nid = wolfSSL_EC_GROUP_get_curve_name(key->group);
        if (nid > 0) {
            curve = wolfSSL_OBJ_nid2ln(nid);
            if (curve != NULL) {
                XFPRINTF(fp, "%*s", indent, "");
                XFPRINTF(fp, "ASN1 OID: %s\n", curve);
            }
            nistName = wolfSSL_EC_curve_nid2nist(nid);
            if (nistName != NULL) {
                XFPRINTF(fp, "%*s", indent, "");
                XFPRINTF(fp, "NIST CURVE: %s\n", nistName);
            }
        }
    }

    if (pubBn != NULL) {
        wolfSSL_BN_free(pubBn);
    }

    WOLFSSL_LEAVE("wolfSSL_EC_KEY_print_fp", ret);

    return ret;
}
#endif /* XFPRINTF && !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM */

#if defined(OPENSSL_ALL)

/* Copies ecc_key into new WOLFSSL_EC_KEY object
 *
 * src  : EC_KEY to duplicate. If EC_KEY is not null, create new EC_KEY and copy
 * internal ecc_key from src to dup.
 *
 * Returns pointer to duplicate EC_KEY.
 */
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_dup(const WOLFSSL_EC_KEY *src)
{
    WOLFSSL_EC_KEY *newKey;
    ecc_key *key, *srcKey;
    int ret;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_dup");

    if (src == NULL || src->internal == NULL || src->group == NULL || \
       src->pub_key == NULL || src->priv_key == NULL) {

        WOLFSSL_MSG("src NULL error");
        return NULL;
    }

    newKey = wolfSSL_EC_KEY_new();
    if (newKey == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_new error");
        return NULL;
    }

    key = (ecc_key*)newKey->internal;
    if (key == NULL) {
        WOLFSSL_MSG("ecc_key NULL error");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }
    srcKey = (ecc_key*)src->internal;

    /* ecc_key */
    /* copy pubkey */
    ret = wc_ecc_copy_point(&srcKey->pubkey, &key->pubkey);
    if (ret != MP_OKAY) {
        WOLFSSL_MSG("wc_ecc_copy_point error");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }

    /* copy private key k */
    ret = mp_copy(&srcKey->k, &key->k);
    if (ret != MP_OKAY) {
        WOLFSSL_MSG("mp_copy error");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }

    /* copy domain parameters */
    if (srcKey->dp) {
        ret = wc_ecc_set_curve(key, 0, srcKey->dp->id);
        if (ret != 0) {
            WOLFSSL_MSG("wc_ecc_set_curve error");
            return NULL;
        }
    }

    key->type  = srcKey->type;
    key->idx   = srcKey->idx;
    key->state = srcKey->state;
    key->flags = srcKey->flags;

    /* Copy group */
    if (newKey->group == NULL) {
        WOLFSSL_MSG("EC_GROUP_new_by_curve_name error");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }

    newKey->group->curve_idx = src->group->curve_idx;
    newKey->group->curve_nid = src->group->curve_nid;
    newKey->group->curve_oid = src->group->curve_oid;

    /* Copy public key */
    if (src->pub_key->internal == NULL || newKey->pub_key->internal == NULL) {
        WOLFSSL_MSG("NULL pub_key error");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }

    /* Copy public key internal */
    ret = wc_ecc_copy_point((ecc_point*)src->pub_key->internal,
                            (ecc_point*)newKey->pub_key->internal);
    if (ret != MP_OKAY) {
        WOLFSSL_MSG("ecc_copy_point error");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }

    /* Copy X, Y, Z */
    newKey->pub_key->X = wolfSSL_BN_dup(src->pub_key->X);
    if (!newKey->pub_key->X && src->pub_key->X) {
        WOLFSSL_MSG("Error copying EC_POINT");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }
    newKey->pub_key->Y = wolfSSL_BN_dup(src->pub_key->Y);
    if (!newKey->pub_key->Y && src->pub_key->Y) {
        WOLFSSL_MSG("Error copying EC_POINT");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }
    newKey->pub_key->Z = wolfSSL_BN_dup(src->pub_key->Z);
    if (!newKey->pub_key->Z && src->pub_key->Z) {
        WOLFSSL_MSG("Error copying EC_POINT");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }

    newKey->pub_key->inSet = src->pub_key->inSet;
    newKey->pub_key->exSet = src->pub_key->exSet;
    newKey->pkcs8HeaderSz = src->pkcs8HeaderSz;

    /* Copy private key */
    if (src->priv_key->internal == NULL || newKey->priv_key->internal == NULL) {
        WOLFSSL_MSG("NULL priv_key error");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }

    /* Free priv_key before call to newKey function */
    wolfSSL_BN_free(newKey->priv_key);
    newKey->priv_key = wolfSSL_BN_dup(src->priv_key);
    if (newKey->priv_key == NULL) {
        WOLFSSL_MSG("BN_newKey error");
        wolfSSL_EC_KEY_free(newKey);
        return NULL;
    }

    return newKey;
}

#endif /* OPENSSL_ALL */

#endif /* !NO_CERTS */

#ifdef ALT_ECC_SIZE
static int SetIndividualInternalEcc(WOLFSSL_BIGNUM* bn, mp_int* mpi)
{
    WOLFSSL_MSG("Entering SetIndividualInternal");

    if (bn == NULL || bn->internal == NULL) {
        WOLFSSL_MSG("bn NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (mpi == NULL) {
        WOLFSSL_MSG("mpi NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (mp_copy((mp_int*)bn->internal, mpi) != MP_OKAY) {
        WOLFSSL_MSG("mp_copy error");
        return WOLFSSL_FATAL_ERROR;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* ALT_ECC_SIZE */

/* EC_POINT Openssl -> WolfSSL */
static int SetECPointInternal(WOLFSSL_EC_POINT *p)
{
    ecc_point* point;
    WOLFSSL_ENTER("SetECPointInternal");

    if (p == NULL || p->internal == NULL) {
        WOLFSSL_MSG("ECPoint NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    point = (ecc_point*)p->internal;

#ifndef ALT_ECC_SIZE
    if (p->X != NULL && SetIndividualInternal(p->X, point->x)
                                                           != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("ecc point X error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (p->Y != NULL && SetIndividualInternal(p->Y, point->y)
                                                           != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("ecc point Y error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (p->Z != NULL && SetIndividualInternal(p->Z, point->z)
                                                           != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("ecc point Z error");
        return WOLFSSL_FATAL_ERROR;
    }
#else
    if (p->X != NULL && SetIndividualInternalEcc(p->X, point->x)
                                                           != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("ecc point X error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (p->Y != NULL && SetIndividualInternalEcc(p->Y, point->y)
                                                           != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("ecc point Y error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (p->Z != NULL && SetIndividualInternalEcc(p->Z, point->z)
                                                           != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("ecc point Z error");
        return WOLFSSL_FATAL_ERROR;
    }
#endif

    p->inSet = 1;

    return WOLFSSL_SUCCESS;
}

/* EC_POINT WolfSSL -> OpenSSL */
static int SetECPointExternal(WOLFSSL_EC_POINT *p)
{
    ecc_point* point;

    WOLFSSL_ENTER("SetECPointExternal");

    if (p == NULL || p->internal == NULL) {
        WOLFSSL_MSG("ECPoint NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    point = (ecc_point*)p->internal;

    if (SetIndividualExternal(&p->X, point->x) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("ecc point X error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&p->Y, point->y) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("ecc point Y error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetIndividualExternal(&p->Z, point->z) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("ecc point Z error");
        return WOLFSSL_FATAL_ERROR;
    }

    p->exSet = 1;

    return WOLFSSL_SUCCESS;
}


/* EC_KEY wolfSSL -> OpenSSL */
int SetECKeyExternal(WOLFSSL_EC_KEY* eckey)
{
    ecc_key* key;

    WOLFSSL_ENTER("SetECKeyExternal");

    if (eckey == NULL || eckey->internal == NULL) {
        WOLFSSL_MSG("ec key NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    key = (ecc_key*)eckey->internal;

    /* set group (OID, nid and idx) */
    eckey->group->curve_oid = ecc_sets[key->idx].oidSum;
    eckey->group->curve_nid = EccEnumToNID(ecc_sets[key->idx].id);
    eckey->group->curve_idx = key->idx;

    if (eckey->pub_key->internal != NULL) {
        /* set the internal public key */
        if (wc_ecc_copy_point(&key->pubkey,
                             (ecc_point*)eckey->pub_key->internal) != MP_OKAY) {
            WOLFSSL_MSG("SetECKeyExternal ecc_copy_point failed");
            return WOLFSSL_FATAL_ERROR;
        }

        /* set the external pubkey (point) */
        if (SetECPointExternal(eckey->pub_key) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetECKeyExternal SetECPointExternal failed");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    /* set the external privkey */
    if (key->type == ECC_PRIVATEKEY) {
        if (SetIndividualExternal(&eckey->priv_key, &key->k) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("ec priv key error");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    eckey->exSet = 1;

    return WOLFSSL_SUCCESS;
}

/* EC_KEY Openssl -> WolfSSL */
int SetECKeyInternal(WOLFSSL_EC_KEY* eckey)
{
    ecc_key* key;

    WOLFSSL_ENTER("SetECKeyInternal");

    if (eckey == NULL || eckey->internal == NULL || eckey->group == NULL) {
        WOLFSSL_MSG("ec key NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    key = (ecc_key*)eckey->internal;

    /* validate group */
    if ((eckey->group->curve_idx < 0) ||
        (wc_ecc_is_valid_idx(eckey->group->curve_idx) == 0)) {
        WOLFSSL_MSG("invalid curve idx");
        return WOLFSSL_FATAL_ERROR;
    }

    /* set group (idx of curve and corresponding domain parameters) */
    key->idx = eckey->group->curve_idx;
    key->dp = &ecc_sets[key->idx];

    /* set pubkey (point) */
    if (eckey->pub_key != NULL) {
        if (SetECPointInternal(eckey->pub_key) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("ec key pub error");
            return WOLFSSL_FATAL_ERROR;
        }

        /* copy over the public point to key */
        if (wc_ecc_copy_point((ecc_point*)eckey->pub_key->internal,
                                                     &key->pubkey) != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_copy_point error");
            return WOLFSSL_FATAL_ERROR;
        }

        /* public key */
        key->type = ECC_PUBLICKEY;
    }

    /* set privkey */
    if (eckey->priv_key != NULL) {
        if (SetIndividualInternal(eckey->priv_key, &key->k)
                                                           != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("ec key priv error");
            return WOLFSSL_FATAL_ERROR;
        }

        /* private key */
        if (!mp_iszero(&key->k))
            key->type = ECC_PRIVATEKEY;
    }

    eckey->inSet = 1;

    return WOLFSSL_SUCCESS;
}

WOLFSSL_EC_POINT *wolfSSL_EC_KEY_get0_public_key(const WOLFSSL_EC_KEY *key)
{
    WOLFSSL_ENTER("wolfSSL_EC_KEY_get0_public_key");

    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_get0_public_key Bad arguments");
        return NULL;
    }

    return key->pub_key;
}

const WOLFSSL_EC_GROUP *wolfSSL_EC_KEY_get0_group(const WOLFSSL_EC_KEY *key)
{
    WOLFSSL_ENTER("wolfSSL_EC_KEY_get0_group");

    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_get0_group Bad arguments");
        return NULL;
    }

    return key->group;
}


/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_EC_KEY_set_private_key(WOLFSSL_EC_KEY *key,
                                   const WOLFSSL_BIGNUM *priv_key)
{
    WOLFSSL_ENTER("wolfSSL_EC_KEY_set_private_key");

    if (key == NULL || priv_key == NULL) {
        WOLFSSL_MSG("Bad arguments");
        return WOLFSSL_FAILURE;
    }

    /* free key if previously set */
    if (key->priv_key != NULL)
        wolfSSL_BN_free(key->priv_key);

    key->priv_key = wolfSSL_BN_dup(priv_key);
    if (key->priv_key == NULL) {
        WOLFSSL_MSG("key ecc priv key NULL");
        return WOLFSSL_FAILURE;
    }

    if (SetECKeyInternal(key) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetECKeyInternal failed");
        wolfSSL_BN_free(key->priv_key);
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}


WOLFSSL_BIGNUM *wolfSSL_EC_KEY_get0_private_key(const WOLFSSL_EC_KEY *key)
{
    WOLFSSL_ENTER("wolfSSL_EC_KEY_get0_private_key");

    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_get0_private_key Bad arguments");
        return NULL;
    }

    if (wolfSSL_BN_is_zero(key->priv_key)) {
        /* return NULL if not set */
        return NULL;
    }

    return key->priv_key;
}

WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new_by_curve_name(int nid)
{
    WOLFSSL_EC_KEY *key;
    int x;
    int eccEnum = NIDToEccEnum(nid);

    WOLFSSL_ENTER("wolfSSL_EC_KEY_new_by_curve_name");

    key = wolfSSL_EC_KEY_new();
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_new failure");
        return NULL;
    }

    /* set the nid of the curve */
    key->group->curve_nid = nid;

    if (eccEnum != -1) {
        /* search and set the corresponding internal curve idx */
        for (x = 0; ecc_sets[x].size != 0; x++)
            if (ecc_sets[x].id == eccEnum) {
                key->group->curve_idx = x;
                key->group->curve_oid = ecc_sets[x].oidSum;
                break;
            }
    }

    return key;
}

const char* wolfSSL_EC_curve_nid2nist(int nid)
{
    const WOLF_EC_NIST_NAME* nist_name;
    for (nist_name = kNistCurves; nist_name->name != NULL; nist_name++) {
        if (nist_name->nid == nid) {
            return nist_name->name;
        }
    }
    return NULL;
}

/**
 * return nist curve id
 * @param name nist curve name
 * @return nist curve id when found, 0 when not found
 */
int wolfSSL_EC_curve_nist2nid(const char* name)
{
    const WOLF_EC_NIST_NAME* nist_name;
    for (nist_name = kNistCurves; nist_name->name != NULL; nist_name++) {
        if (XSTRCMP(nist_name->name, name) == 0) {
            return nist_name->nid;
        }
    }
    return 0;
}

static void InitwolfSSL_ECKey(WOLFSSL_EC_KEY* key)
{
    if (key) {
        key->group    = NULL;
        key->pub_key  = NULL;
        key->priv_key = NULL;
        key->internal = NULL;
        key->inSet    = 0;
        key->exSet    = 0;
        key->form     = POINT_CONVERSION_UNCOMPRESSED;
    }
}

WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new_ex(void* heap, int devId)
{
    WOLFSSL_EC_KEY *external;
    WOLFSSL_ENTER("wolfSSL_EC_KEY_new");

    external = (WOLFSSL_EC_KEY*)XMALLOC(sizeof(WOLFSSL_EC_KEY), heap,
                                        DYNAMIC_TYPE_ECC);
    if (external == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_new malloc WOLFSSL_EC_KEY failure");
        return NULL;
    }
    XMEMSET(external, 0, sizeof(WOLFSSL_EC_KEY));
    external->heap = heap;

    InitwolfSSL_ECKey(external);

    external->refCount = 1;
#ifndef SINGLE_THREADED
    if (wc_InitMutex(&external->refMutex) != 0) {
        WOLFSSL_MSG("wc_InitMutex WOLFSSL_EC_KEY failure");
        XFREE(external, heap, DYNAMIC_TYPE_ECC);
        return NULL;
    }
#endif

    external->internal = (ecc_key*)XMALLOC(sizeof(ecc_key), heap,
                                           DYNAMIC_TYPE_ECC);
    if (external->internal == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_new malloc ecc key failure");
        goto error;
    }
    XMEMSET(external->internal, 0, sizeof(ecc_key));

    if (wc_ecc_init_ex((ecc_key*)external->internal, heap, devId) != 0) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_new init ecc key failure");
        goto error;
    }

    /* Group unknown at creation */
    external->group = wolfSSL_EC_GROUP_new_by_curve_name(NID_undef);
    if (external->group == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_new malloc WOLFSSL_EC_GROUP failure");
        goto error;
    }

    /* public key */
    external->pub_key = wolfSSL_EC_POINT_new(external->group);
    if (external->pub_key == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_new failure");
        goto error;
    }

    /* private key */
    external->priv_key = wolfSSL_BN_new();
    if (external->priv_key == NULL) {
        WOLFSSL_MSG("wolfSSL_BN_new failure");
        goto error;
    }

    return external;
error:
    wolfSSL_EC_KEY_free(external);
    return NULL;
}

WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new(void)
{
    return wolfSSL_EC_KEY_new_ex(NULL, INVALID_DEVID);
}

void wolfSSL_EC_KEY_free(WOLFSSL_EC_KEY *key)
{
    int doFree = 0;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_free");

    if (key != NULL) {
        void* heap = key->heap;

    #ifndef SINGLE_THREADED
        if (wc_LockMutex(&key->refMutex) != 0) {
            WOLFSSL_MSG("Could not lock EC_KEY mutex");
            return;
        }
    #endif

        /* only free if all references to it are done */
        key->refCount--;
        if (key->refCount == 0) {
            doFree = 1;
        }
    #ifndef SINGLE_THREADED
        wc_UnLockMutex(&key->refMutex);
    #endif

        if (doFree == 0) {
            return;
        }

        if (key->internal != NULL) {
            wc_ecc_free((ecc_key*)key->internal);
            XFREE(key->internal, heap, DYNAMIC_TYPE_ECC);
        }
        wolfSSL_BN_free(key->priv_key);
        wolfSSL_EC_POINT_free(key->pub_key);
        wolfSSL_EC_GROUP_free(key->group);
        InitwolfSSL_ECKey(key); /* set back to NULLs for safety */

        XFREE(key, heap, DYNAMIC_TYPE_ECC);
        (void)heap;
        /* key = NULL, don't try to access or double free it */
    }
}

/* Increments ref count of WOLFSSL_EC_KEY.
 * Return WOLFSSL_SUCCESS on success, WOLFSSL_FAILURE on error */
int wolfSSL_EC_KEY_up_ref(WOLFSSL_EC_KEY* key)
{
    if (key) {
    #ifndef SINGLE_THREADED
        if (wc_LockMutex(&key->refMutex) != 0) {
            WOLFSSL_MSG("Failed to lock EC_KEY mutex");
        }
    #endif
        key->refCount++;
    #ifndef SINGLE_THREADED
        wc_UnLockMutex(&key->refMutex);
    #endif
        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}

/* set the group in WOLFSSL_EC_KEY and return WOLFSSL_SUCCESS on success */
int wolfSSL_EC_KEY_set_group(WOLFSSL_EC_KEY *key, WOLFSSL_EC_GROUP *group)
{
    if (key == NULL || group == NULL)
        return WOLFSSL_FAILURE;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_set_group");

    if (key->group != NULL) {
        /* free the current group */
        wolfSSL_EC_GROUP_free(key->group);
    }

    key->group = wolfSSL_EC_GROUP_dup(group);
    if (key->group == NULL) {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}


int wolfSSL_EC_KEY_generate_key(WOLFSSL_EC_KEY *key)
{
    int     initTmpRng = 0;
    int     eccEnum;
    WC_RNG* rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRNG = NULL;
#else
    WC_RNG  tmpRNG[1];
#endif
    int ret;
    ecc_key* ecKey;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_generate_key");

    if (key == NULL || key->internal == NULL ||
        key->group == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key Bad arguments");
        return 0;
    }
    if (key->group->curve_idx < 0) {
        /* generate key using the default curve */
        /* group should be set, but to retain compat use index 0 */
        key->group->curve_idx = ECC_CURVE_DEF;
    }

#ifdef WOLFSSL_SMALL_STACK
    tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
    if (tmpRNG == NULL)
        return 0;
#endif

    if (wc_InitRng(tmpRNG) == 0) {
        rng = tmpRNG;
        initTmpRng = 1;
    }
    else {
        WOLFSSL_MSG("Bad RNG Init, trying global");
        rng = wolfssl_get_global_rng();
    }

    if (rng == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key failed to set RNG");
#ifdef WOLFSSL_SMALL_STACK
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
#endif
        return 0;
    }

    /* NIDToEccEnum returns -1 for invalid NID so if key->group->curve_nid
     * is 0 then pass ECC_CURVE_DEF as arg */
    ecKey = (ecc_key*)key->internal;
    eccEnum = key->group->curve_nid ?
            NIDToEccEnum(key->group->curve_nid) : ECC_CURVE_DEF;
    ret = wc_ecc_make_key_ex(rng, 0, ecKey, eccEnum);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &ecKey->asyncDev, WC_ASYNC_FLAG_NONE);
#endif

    if (ret != 0) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key wc_ecc_make_key failed");
#ifdef WOLFSSL_SMALL_STACK
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
#endif
        return 0;
    }

    if (initTmpRng)
        wc_FreeRng(tmpRNG);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
#endif

    if (SetECKeyExternal(key) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key SetECKeyExternal failed");
        return 0;
    }

    return 1;
}

#ifndef NO_WOLFSSL_STUB
void wolfSSL_EC_KEY_set_asn1_flag(WOLFSSL_EC_KEY *key, int asn1_flag)
{
    (void)key;
    (void)asn1_flag;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_set_asn1_flag");
    WOLFSSL_STUB("EC_KEY_set_asn1_flag");
}
#endif

static int setupPoint(const WOLFSSL_EC_POINT *p) {
    if (!p) {
        return WOLFSSL_FAILURE;
    }
    if (p->inSet == 0) {
        WOLFSSL_MSG("No ECPoint internal set, do it");

        if (SetECPointInternal((WOLFSSL_EC_POINT *)p) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetECPointInternal SetECPointInternal failed");
            return WOLFSSL_FAILURE;
        }
    }
    return WOLFSSL_SUCCESS;
}

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_EC_KEY_set_public_key(WOLFSSL_EC_KEY *key,
                                  const WOLFSSL_EC_POINT *pub)
{
    ecc_point *pub_p, *key_p;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_set_public_key");

    if (key == NULL || key->internal == NULL ||
        pub == NULL || pub->internal == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_set_public_key Bad arguments");
        return WOLFSSL_FAILURE;
    }

    if (key->inSet == 0) {
        if (SetECKeyInternal(key) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetECKeyInternal failed");
            return WOLFSSL_FAILURE;
        }
    }

    if (setupPoint(pub) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    pub_p = (ecc_point*)pub->internal;
    key_p = (ecc_point*)key->pub_key->internal;

    /* create new point if required */
    if (key_p == NULL)
        key_p = wc_ecc_new_point();

    if (key_p == NULL) {
        WOLFSSL_MSG("key ecc point NULL");
        return WOLFSSL_FAILURE;
    }

    if (wc_ecc_copy_point(pub_p, key_p) != MP_OKAY) {
        WOLFSSL_MSG("ecc_copy_point failure");
        return WOLFSSL_FAILURE;
    }

    if (SetECPointExternal(key->pub_key) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetECKeyInternal failed");
        return WOLFSSL_FAILURE;
    }

    if (SetECKeyInternal(key) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetECKeyInternal failed");
        return WOLFSSL_FAILURE;
    }

    wolfSSL_EC_POINT_dump("pub", pub);
    wolfSSL_EC_POINT_dump("key->pub_key", key->pub_key);

    return WOLFSSL_SUCCESS;
}

int wolfSSL_EC_KEY_check_key(const WOLFSSL_EC_KEY *key)
{
    WOLFSSL_ENTER("wolfSSL_EC_KEY_check_key");

    if (key == NULL || key->internal == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    if (key->inSet == 0) {
        if (SetECKeyInternal((WOLFSSL_EC_KEY*)key) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetECKeyInternal failed");
            return WOLFSSL_FAILURE;
        }
    }

    return wc_ecc_check_key((ecc_key*)key->internal) == 0 ?
            WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}
/* End EC_KEY */

/* Calculate and return maximum size of the ECDSA signature for the curve */
int wolfSSL_ECDSA_size(const WOLFSSL_EC_KEY *key)
{
    const EC_GROUP *group;
    int bits, bytes;
    word32 headerSz = SIG_HEADER_SZ; /* 2*ASN_TAG + 2*LEN(ENUM) */

    if (key == NULL) {
        return WOLFSSL_FAILURE;
    }

    if ((group = wolfSSL_EC_KEY_get0_group(key)) == NULL) {
        return WOLFSSL_FAILURE;
    }
    if ((bits = wolfSSL_EC_GROUP_order_bits(group)) == 0) {
        /* group is not set */
        return WOLFSSL_FAILURE;
    }

    bytes = (bits + 7) / 8;  /* bytes needed to hold bits */
    return headerSz +
            ECC_MAX_PAD_SZ + /* possible leading zeroes in r and s */
            bytes + bytes;   /* r and s */
}

int wolfSSL_ECDSA_sign(int type,
    const unsigned char *digest, int digestSz,
    unsigned char *sig, unsigned int *sigSz, WOLFSSL_EC_KEY *key)
{
    int ret = WOLFSSL_SUCCESS;
    WC_RNG* rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRNG = NULL;
#else
    WC_RNG  tmpRNG[1];
#endif
    int initTmpRng = 0;

    WOLFSSL_ENTER("wolfSSL_ECDSA_sign");

    if (!key) {
        return WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_SMALL_STACK
    tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
    if (tmpRNG == NULL)
        return WOLFSSL_FAILURE;
#endif

    if (wc_InitRng(tmpRNG) == 0) {
        rng = tmpRNG;
        initTmpRng = 1;
    }
    else {
        WOLFSSL_MSG("Bad RNG Init, trying global");
        rng = wolfssl_get_global_rng();
    }
    if (rng) {
        if (wc_ecc_sign_hash(digest, digestSz, sig, sigSz, rng,
                (ecc_key*)key->internal) != 0) {
            ret = WOLFSSL_FAILURE;
        }
        if (initTmpRng) {
            wc_FreeRng(tmpRNG);
        }
    } else {
        ret = WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (tmpRNG)
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
#endif

    (void)type;
    return ret;
}

int wolfSSL_ECDSA_verify(int type,
    const unsigned char *digest, int digestSz,
    const unsigned char *sig, int sigSz, WOLFSSL_EC_KEY *key)
{
    int ret = WOLFSSL_SUCCESS;
    int verify = 0;

    WOLFSSL_ENTER("wolfSSL_ECDSA_verify");

    if (key == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (wc_ecc_verify_hash(sig, sigSz, digest, digestSz,
            &verify, (ecc_key*)key->internal) != 0) {
        ret = WOLFSSL_FAILURE;
    }
    if (ret == WOLFSSL_SUCCESS && verify != 1) {
        WOLFSSL_MSG("wolfSSL_ECDSA_verify failed");
        ret = WOLFSSL_FAILURE;
    }

    (void)type;
    return ret;
}

#ifndef HAVE_SELFTEST
/* ECC point compression types were not included in selftest ecc.h */

char* wolfSSL_EC_POINT_point2hex(const WOLFSSL_EC_GROUP* group,
                                 const WOLFSSL_EC_POINT* point, int form,
                                 WOLFSSL_BN_CTX* ctx)
{
    static const char* hexDigit = "0123456789ABCDEF";
    char* hex = NULL;
    int id;
    int i, sz, len;

    (void)ctx;

    if (group == NULL || point == NULL)
        return NULL;

    id = wc_ecc_get_curve_id(group->curve_idx);

    if ((sz = wc_ecc_get_curve_size_from_id(id)) < 0)
        return NULL;

    len = sz + 1;
    if (form == POINT_CONVERSION_UNCOMPRESSED)
        len += sz;
    hex = (char*)XMALLOC(2 * len + 1, NULL, DYNAMIC_TYPE_ECC);
    if (hex == NULL)
        return NULL;
    XMEMSET(hex, 0, 2 * len + 1);

    /* Put in x-ordinate after format byte. */
    i = sz - mp_unsigned_bin_size((mp_int*)point->X->internal) + 1;
    if (mp_to_unsigned_bin((mp_int*)point->X->internal, (byte*)(hex + i)) < 0) {
        XFREE(hex,  NULL, DYNAMIC_TYPE_ECC);
        return NULL;
    }

    if (form == POINT_CONVERSION_COMPRESSED) {
        hex[0] = mp_isodd((mp_int*)point->Y->internal) ? ECC_POINT_COMP_ODD :
                                                         ECC_POINT_COMP_EVEN;
    }
    else {
        hex[0] = ECC_POINT_UNCOMP;
        /* Put in y-ordinate after x-ordinate */
        i = 1 + 2 * sz - mp_unsigned_bin_size((mp_int*)point->Y->internal);
        if (mp_to_unsigned_bin((mp_int*)point->Y->internal,
                                                        (byte*)(hex + i)) < 0) {
            XFREE(hex,  NULL, DYNAMIC_TYPE_ECC);
            return NULL;
        }
    }

    for (i = len-1; i >= 0; i--) {
        byte b = hex[i];
        hex[i * 2 + 1] = hexDigit[b  & 0xf];
        hex[i * 2    ] = hexDigit[b >>   4];
    }

    return hex;
}

#endif /* HAVE_SELFTEST */

void wolfSSL_EC_POINT_dump(const char *msg, const WOLFSSL_EC_POINT *p)
{
#if defined(DEBUG_WOLFSSL)
    char *num;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_dump");

    if (!WOLFSSL_IS_DEBUG_ON() || wolfSSL_GetLoggingCb()) {
        return;
    }

    if (p == NULL) {
        printf("%s = NULL", msg);
        return;
    }

    printf("%s:\n\tinSet=%d, exSet=%d\n", msg, p->inSet, p->exSet);
    num = wolfSSL_BN_bn2hex(p->X);
    printf("\tX = %s\n", num);
    XFREE(num, NULL, DYNAMIC_TYPE_OPENSSL);
    num = wolfSSL_BN_bn2hex(p->Y);
    printf("\tY = %s\n", num);
    XFREE(num, NULL, DYNAMIC_TYPE_OPENSSL);
    num = wolfSSL_BN_bn2hex(p->Z);
    printf("\tZ = %s\n", num);
    XFREE(num, NULL, DYNAMIC_TYPE_OPENSSL);
#else
    (void)msg;
    (void)p;
#endif
}

/* Start EC_GROUP */

/* return code compliant with OpenSSL :
 *   0 if equal, 1 if not and -1 in case of error
 */
int wolfSSL_EC_GROUP_cmp(const WOLFSSL_EC_GROUP *a, const WOLFSSL_EC_GROUP *b,
                         WOLFSSL_BN_CTX *ctx)
{
    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_EC_GROUP_cmp");

    if (a == NULL || b == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_cmp Bad arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    /* ok */
    if ((a->curve_idx == b->curve_idx) && (a->curve_nid == b->curve_nid))
        return 0;

    /* ko */
    return 1;
}

WOLFSSL_EC_GROUP *wolfSSL_EC_GROUP_dup(const WOLFSSL_EC_GROUP *src)
{
    if (!src)
        return NULL;
    return wolfSSL_EC_GROUP_new_by_curve_name(src->curve_nid);
}

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
const WOLFSSL_EC_METHOD* wolfSSL_EC_GROUP_method_of(
                                                const WOLFSSL_EC_GROUP *group)
{
    return group;
}

int wolfSSL_EC_METHOD_get_field_type(const WOLFSSL_EC_METHOD *meth)
{
    if (meth) {
        return NID_X9_62_prime_field;
    }
    return WOLFSSL_FAILURE;
}

void wolfSSL_EC_GROUP_free(WOLFSSL_EC_GROUP *group)
{
    WOLFSSL_ENTER("wolfSSL_EC_GROUP_free");

    XFREE(group, NULL, DYNAMIC_TYPE_ECC);
    /* group = NULL, don't try to access or double free it */
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA
#ifndef NO_WOLFSSL_STUB
void wolfSSL_EC_GROUP_set_asn1_flag(WOLFSSL_EC_GROUP *group, int flag)
{
    (void)group;
    (void)flag;

    WOLFSSL_ENTER("wolfSSL_EC_GROUP_set_asn1_flag");
    WOLFSSL_STUB("EC_GROUP_set_asn1_flag");
}
#endif

WOLFSSL_EC_GROUP *wolfSSL_EC_GROUP_new_by_curve_name(int nid)
{
    WOLFSSL_EC_GROUP *g;
    int x, eccEnum;

    WOLFSSL_ENTER("wolfSSL_EC_GROUP_new_by_curve_name");

    /* curve group */
    g = (WOLFSSL_EC_GROUP*)XMALLOC(sizeof(WOLFSSL_EC_GROUP), NULL,
                                    DYNAMIC_TYPE_ECC);
    if (g == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_new_by_curve_name malloc failure");
        return NULL;
    }
    XMEMSET(g, 0, sizeof(WOLFSSL_EC_GROUP));

    /* set the nid of the curve */
    g->curve_nid = nid;
    g->curve_idx = -1;

    /* If NID passed in is OpenSSL type, convert it to ecc_curve_id enum */
    eccEnum = NIDToEccEnum(nid);
    if (eccEnum != -1) {
        /* search and set the corresponding internal curve idx */
        for (x = 0; ecc_sets[x].size != 0; x++) {
            if (ecc_sets[x].id == eccEnum) {
                g->curve_idx = x;
                g->curve_oid = ecc_sets[x].oidSum;
                break;
            }
        }
    }

    return g;
}

/* return code compliant with OpenSSL :
 *   the curve nid if success, 0 if error
 */
int wolfSSL_EC_GROUP_get_curve_name(const WOLFSSL_EC_GROUP *group)
{
    int nid;
    WOLFSSL_ENTER("wolfSSL_EC_GROUP_get_curve_name");

    if (group == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_curve_name Bad arguments");
        return WOLFSSL_FAILURE;
    }

    /* If curve_nid is ECC Enum type, return corresponding OpenSSL nid */
    if ((nid = EccEnumToNID(group->curve_nid)) != -1)
        return nid;

    return group->curve_nid;
}

/* return code compliant with OpenSSL :
 *   the degree of the curve if success, 0 if error
 */
int wolfSSL_EC_GROUP_get_degree(const WOLFSSL_EC_GROUP *group)
{
    int nid;
    int tmp;

    WOLFSSL_ENTER("wolfSSL_EC_GROUP_get_degree");

    if (group == NULL || group->curve_idx < 0) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_degree Bad arguments");
        return WOLFSSL_FAILURE;
    }

    /* If curve_nid passed in is an ecc_curve_id enum, convert it to the
        corresponding OpenSSL NID */
    tmp = EccEnumToNID(group->curve_nid);
    if (tmp != -1) {
        nid = tmp;
    }
    else {
        nid = group->curve_nid;
    }

    switch(nid) {
        case NID_secp112r1:
        case NID_secp112r2:
            return 112;
        case NID_secp128r1:
        case NID_secp128r2:
            return 128;
        case NID_secp160k1:
        case NID_secp160r1:
        case NID_secp160r2:
        case NID_brainpoolP160r1:
            return 160;
        case NID_secp192k1:
        case NID_brainpoolP192r1:
        case NID_X9_62_prime192v1:
            return 192;
        case NID_secp224k1:
        case NID_secp224r1:
        case NID_brainpoolP224r1:
            return 224;
        case NID_secp256k1:
        case NID_brainpoolP256r1:
        case NID_X9_62_prime256v1:
            return 256;
        case NID_brainpoolP320r1:
            return 320;
        case NID_secp384r1:
        case NID_brainpoolP384r1:
            return 384;
        case NID_secp521r1:
            return 521;
        case NID_brainpoolP512r1:
            return 512;
        default:
            return WOLFSSL_FAILURE;
    }
}

/* Converts OpenSSL NID value of ECC curves to the associated enum values in
   ecc_curve_id, used by ecc_sets[].*/
int NIDToEccEnum(int n)
{
    WOLFSSL_ENTER("NIDToEccEnum()");

    switch(n) {
        case NID_X9_62_prime192v1:
            return ECC_SECP192R1;
        case NID_X9_62_prime192v2:
            return ECC_PRIME192V2;
        case NID_X9_62_prime192v3:
            return ECC_PRIME192V3;
        case NID_X9_62_prime239v1:
            return ECC_PRIME239V1;
        case NID_X9_62_prime239v2:
            return ECC_PRIME239V2;
        case NID_X9_62_prime239v3:
            return ECC_PRIME239V3;
        case NID_X9_62_prime256v1:
            return ECC_SECP256R1;
        case NID_secp112r1:
            return ECC_SECP112R1;
        case NID_secp112r2:
            return ECC_SECP112R2;
        case NID_secp128r1:
            return ECC_SECP128R1;
        case NID_secp128r2:
            return ECC_SECP128R2;
        case NID_secp160r1:
            return ECC_SECP160R1;
        case NID_secp160r2:
            return ECC_SECP160R2;
        case NID_secp224r1:
            return ECC_SECP224R1;
        case NID_secp384r1:
            return ECC_SECP384R1;
        case NID_secp521r1:
            return ECC_SECP521R1;
        case NID_secp160k1:
            return ECC_SECP160K1;
        case NID_secp192k1:
            return ECC_SECP192K1;
        case NID_secp224k1:
            return ECC_SECP224K1;
        case NID_secp256k1:
            return ECC_SECP256K1;
        case NID_brainpoolP160r1:
            return ECC_BRAINPOOLP160R1;
        case NID_brainpoolP192r1:
            return ECC_BRAINPOOLP192R1;
        case NID_brainpoolP224r1:
            return ECC_BRAINPOOLP224R1;
        case NID_brainpoolP256r1:
            return ECC_BRAINPOOLP256R1;
        case NID_brainpoolP320r1:
            return ECC_BRAINPOOLP320R1;
        case NID_brainpoolP384r1:
            return ECC_BRAINPOOLP384R1;
        case NID_brainpoolP512r1:
            return ECC_BRAINPOOLP512R1;
        default:
            WOLFSSL_MSG("NID not found");
            return -1;
    }
}

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_EC_GROUP_get_order(const WOLFSSL_EC_GROUP *group,
                               WOLFSSL_BIGNUM *order, WOLFSSL_BN_CTX *ctx)
{
    (void)ctx;

    if (group == NULL || order == NULL || order->internal == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_order NULL error");
        return WOLFSSL_FAILURE;
    }

    if (mp_init((mp_int*)order->internal) != MP_OKAY) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_order mp_init failure");
        return WOLFSSL_FAILURE;
    }

    if (mp_read_radix((mp_int*)order->internal,
                  ecc_sets[group->curve_idx].order, MP_RADIX_HEX) != MP_OKAY) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_get_order mp_read order failure");
        mp_clear((mp_int*)order->internal);
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}

int wolfSSL_EC_GROUP_order_bits(const WOLFSSL_EC_GROUP *group)
{
    int ret;
    mp_int order;

    if (group == NULL || group->curve_idx < 0) {
        WOLFSSL_MSG("wolfSSL_EC_GROUP_order_bits NULL error");
        return 0;
    }

    ret = mp_init(&order);
    if (ret == 0) {
        ret = mp_read_radix(&order, ecc_sets[group->curve_idx].order,
            MP_RADIX_HEX);
        if (ret == 0)
            ret = mp_count_bits(&order);
        mp_clear(&order);
    }

    return ret;
}

/* End EC_GROUP */

/* Start EC_POINT */

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_ECPoint_i2d(const WOLFSSL_EC_GROUP *group,
                        const WOLFSSL_EC_POINT *p,
                        unsigned char *out, unsigned int *len)
{
    int err;

    WOLFSSL_ENTER("wolfSSL_ECPoint_i2d");

    if (group == NULL || p == NULL || len == NULL) {
        WOLFSSL_MSG("wolfSSL_ECPoint_i2d NULL error");
        return WOLFSSL_FAILURE;
    }

    if (setupPoint(p) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    if (out != NULL) {
        wolfSSL_EC_POINT_dump("i2d p", p);
    }

    err = wc_ecc_export_point_der(group->curve_idx, (ecc_point*)p->internal,
                                  out, len);
    if (err != MP_OKAY && !(out == NULL && err == LENGTH_ONLY_E)) {
        WOLFSSL_MSG("wolfSSL_ECPoint_i2d wc_ecc_export_point_der failed");
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_ECPoint_d2i(unsigned char *in, unsigned int len,
                        const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *p)
{
    WOLFSSL_ENTER("wolfSSL_ECPoint_d2i");

    if (group == NULL || p == NULL || p->internal == NULL || in == NULL) {
        WOLFSSL_MSG("wolfSSL_ECPoint_d2i NULL error");
        return WOLFSSL_FAILURE;
    }

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2)))
    if (wc_ecc_import_point_der_ex(in, len, group->curve_idx,
                                   (ecc_point*)p->internal, 0) != MP_OKAY) {
        WOLFSSL_MSG("wc_ecc_import_point_der_ex failed");
       return WOLFSSL_FAILURE;
    }
#else
    /* ECC_POINT_UNCOMP is not defined CAVP self test so use magic number */
    if (in[0] == 0x04) {
        if (wc_ecc_import_point_der(in, len, group->curve_idx,
                                    (ecc_point*)p->internal) != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_import_point_der failed");
            return WOLFSSL_FAILURE;
        }
    }
    else {
        WOLFSSL_MSG("Only uncompressed points supported with HAVE_SELFTEST");
        return WOLFSSL_FAILURE;
    }
#endif

    /* Set new external point */
    if (SetECPointExternal(p) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetECPointExternal failed");
        return WOLFSSL_FAILURE;
    }

    wolfSSL_EC_POINT_dump("d2i p", p);

    return WOLFSSL_SUCCESS;
}

size_t wolfSSL_EC_POINT_point2oct(const WOLFSSL_EC_GROUP *group,
                                  const WOLFSSL_EC_POINT *p,
                                  char form,
                                  byte *buf, size_t len, WOLFSSL_BN_CTX *ctx)
{
    word32 min_len = (word32)len;
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
    int compressed = form == POINT_CONVERSION_COMPRESSED ? 1 : 0;
#endif /* !HAVE_SELFTEST */

    WOLFSSL_ENTER("EC_POINT_point2oct");

    if (!group || !p) {
        return WOLFSSL_FAILURE;
    }

    if (setupPoint(p) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    if (wolfSSL_EC_POINT_is_at_infinity(group, p)) {
        /* encodes to a single 0 octet */
        if (buf != NULL) {
            if (len < 1) {
                ECerr(EC_F_EC_GFP_SIMPLE_POINT2OCT, EC_R_BUFFER_TOO_SMALL);
                return WOLFSSL_FAILURE;
            }
            buf[0] = 0;
        }
        return 1;
    }

    if (form != POINT_CONVERSION_UNCOMPRESSED
#ifndef HAVE_SELFTEST
            && form != POINT_CONVERSION_COMPRESSED
#endif /* !HAVE_SELFTEST */
            ) {
        WOLFSSL_MSG("Unsupported curve form");
        return WOLFSSL_FAILURE;
    }

#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
    if (wc_ecc_export_point_der_ex(group->curve_idx, (ecc_point*)p->internal,
               buf, &min_len, compressed) != (buf ? MP_OKAY : LENGTH_ONLY_E)) {
        return WOLFSSL_FAILURE;
    }
#else
    if (wc_ecc_export_point_der(group->curve_idx, (ecc_point*)p->internal,
                                buf, &min_len) != (buf ? MP_OKAY : LENGTH_ONLY_E)) {
        return WOLFSSL_FAILURE;
    }
#endif /* !HAVE_SELFTEST */

    (void)ctx;

    return (size_t)min_len;
}


int wolfSSL_EC_POINT_oct2point(const WOLFSSL_EC_GROUP *group,
                               WOLFSSL_EC_POINT *p, const unsigned char *buf,
                               size_t len, WOLFSSL_BN_CTX *ctx)
{
    WOLFSSL_ENTER("wolfSSL_EC_POINT_oct2point");

    if (!group || !p) {
        return WOLFSSL_FAILURE;
    }

    (void)ctx;

    return wolfSSL_ECPoint_d2i((unsigned char*)buf, (unsigned int)len, group, p);
}


WOLFSSL_EC_KEY *wolfSSL_o2i_ECPublicKey(WOLFSSL_EC_KEY **a, const unsigned char **in,
                                        long len)
{
    WOLFSSL_EC_KEY* ret;

    WOLFSSL_ENTER("wolfSSL_o2i_ECPublicKey");

    if (!a || !*a || !(*a)->group || !in || !*in || len <= 0) {
        WOLFSSL_MSG("wolfSSL_o2i_ECPublicKey Bad arguments");
        return NULL;
    }

    ret = *a;

    if (wolfSSL_EC_POINT_oct2point(ret->group, ret->pub_key, *in, len, NULL)
            != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_oct2point error");
        return NULL;
    }

    *in += len;
    return ret;
}

int wolfSSL_i2o_ECPublicKey(const WOLFSSL_EC_KEY *in, unsigned char **out)
{
    size_t len;
    unsigned char *tmp = NULL;
    char form;
    WOLFSSL_ENTER("wolfSSL_i2o_ECPublicKey");

    if (!in) {
        WOLFSSL_MSG("wolfSSL_i2o_ECPublicKey Bad arguments");
        return WOLFSSL_FAILURE;
    }

    if (!in->exSet) {
        if (SetECKeyExternal((WOLFSSL_EC_KEY*)in) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetECKeyExternal failure");
            return WOLFSSL_FAILURE;
        }
    }

#ifdef HAVE_COMP_KEY
    /* Default to compressed form if not set */
    form = in->form == POINT_CONVERSION_UNCOMPRESSED ?
            POINT_CONVERSION_UNCOMPRESSED:
            POINT_CONVERSION_COMPRESSED;
#else
    form = POINT_CONVERSION_UNCOMPRESSED;
#endif

    len = wolfSSL_EC_POINT_point2oct(in->group, in->pub_key, form,
                                     NULL, 0, NULL);

    if (len != WOLFSSL_FAILURE && out) {
        if (!*out) {
            if (!(tmp = (unsigned char*)XMALLOC(len, NULL,
                                                DYNAMIC_TYPE_OPENSSL))) {
                WOLFSSL_MSG("malloc failed");
                return WOLFSSL_FAILURE;
            }
            *out = tmp;
        }

        if (wolfSSL_EC_POINT_point2oct(in->group, in->pub_key, form, *out,
                                       len, NULL) == WOLFSSL_FAILURE) {
            if (tmp) {
                XFREE(tmp, NULL, DYNAMIC_TYPE_OPENSSL);
                *out = NULL;
            }
            return WOLFSSL_FAILURE;
        }

        if (!tmp) {
            /* Move buffer forward if it was not alloced in this function */
            *out += len;
        }
    }

    return (int)len;
}

#ifdef HAVE_ECC_KEY_IMPORT
WOLFSSL_EC_KEY *wolfSSL_d2i_ECPrivateKey(WOLFSSL_EC_KEY **key, const unsigned char **in,
                                         long len)
{
    word32 idx = 0;
    WOLFSSL_EC_KEY *eckey = NULL;
    WOLFSSL_ENTER("wolfSSL_d2i_ECPrivateKey");

    if (!in || !*in || len <= 0) {
        WOLFSSL_MSG("wolfSSL_d2i_ECPrivateKey Bad arguments");
        return NULL;
    }

    if (!(eckey = wolfSSL_EC_KEY_new())) {
        WOLFSSL_MSG("wolfSSL_EC_KEY_new error");
        return NULL;
    }

    if (wc_EccPrivateKeyDecode(*in, &idx, (ecc_key*)eckey->internal,
            (word32)len) != 0) {
        WOLFSSL_MSG("wc_EccPrivateKeyDecode error");
        goto error;
    }

    eckey->inSet = 1;

    if (SetECKeyExternal(eckey) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetECKeyExternal error");
        goto error;
    }

    if (key) {
        *key = eckey;
    }

    return eckey;

error:
    wolfSSL_EC_KEY_free(eckey);
    return NULL;
}
#endif /* HAVE_ECC_KEY_IMPORT */

int wolfSSL_i2d_ECPrivateKey(const WOLFSSL_EC_KEY *in, unsigned char **out)
{
    word32 len;
    byte* buf = NULL;
    WOLFSSL_ENTER("wolfSSL_i2d_ECPrivateKey");

    if (!in) {
        WOLFSSL_MSG("wolfSSL_i2d_ECPrivateKey Bad arguments");
        return WOLFSSL_FAILURE;
    }

    if (!in->inSet && SetECKeyInternal(
            (WOLFSSL_EC_KEY*)in) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetECKeyInternal error");
        return WOLFSSL_FAILURE;
    }

    if ((len = wc_EccKeyDerSize((ecc_key*)in->internal, 0)) <= 0) {
        WOLFSSL_MSG("wc_EccKeyDerSize error");
        return WOLFSSL_FAILURE;
    }

    if (out) {
        if (!(buf = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER))) {
            WOLFSSL_MSG("tmp buffer malloc error");
            return WOLFSSL_FAILURE;
        }

        if (wc_EccPrivateKeyToDer((ecc_key*)in->internal, buf, len) < 0) {
            WOLFSSL_MSG("wc_EccPrivateKeyToDer error");
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFSSL_FAILURE;
        }

        if (*out) {
            XMEMCPY(*out, buf, len);
            XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        else {
            *out = buf;
        }
    }

    return (int)len;
}

void wolfSSL_EC_KEY_set_conv_form(WOLFSSL_EC_KEY *eckey, char form)
{
    if (eckey && (form == POINT_CONVERSION_UNCOMPRESSED
#ifdef HAVE_COMP_KEY
                  || form == POINT_CONVERSION_COMPRESSED
#endif
                  )) {
        eckey->form = form;
    } else {
        WOLFSSL_MSG("Incorrect form or HAVE_COMP_KEY not compiled in");
    }
}

point_conversion_form_t wolfSSL_EC_KEY_get_conv_form(const WOLFSSL_EC_KEY* key)
{
    if (key != NULL) {
        return key->form;
    }

    return -1;
}

/* wolfSSL_EC_POINT_point2bn should return "in" if not null */
WOLFSSL_BIGNUM *wolfSSL_EC_POINT_point2bn(const WOLFSSL_EC_GROUP *group,
    const WOLFSSL_EC_POINT *p, char form, WOLFSSL_BIGNUM *in,
    WOLFSSL_BN_CTX *ctx)
{
    size_t len;
    byte *buf;
    WOLFSSL_BIGNUM *ret = NULL;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_oct2point");

    if (!group || !p) {
        return NULL;
    }

    if ((len = wolfSSL_EC_POINT_point2oct(group, p, form,
                                          NULL, 0, ctx)) == WOLFSSL_FAILURE) {
        return NULL;
    }

    if (!(buf = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER))) {
        WOLFSSL_MSG("malloc failed");
        return NULL;
    }

    if (wolfSSL_EC_POINT_point2oct(group, p, form,
                                   buf, len, ctx) == len) {
        ret = wolfSSL_BN_bin2bn(buf, (int)len, in);
    }

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#if defined(USE_ECC_B_PARAM) && (!defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
int wolfSSL_EC_POINT_is_on_curve(const WOLFSSL_EC_GROUP *group,
                                 const WOLFSSL_EC_POINT *point,
                                 WOLFSSL_BN_CTX *ctx)
{
    (void)ctx;
    WOLFSSL_ENTER("wolfSSL_EC_POINT_is_on_curve");

    if (!group || !point) {
        WOLFSSL_MSG("Invalid arguments");
        return WOLFSSL_FAILURE;
    }

    if (!point->inSet && SetECPointInternal((WOLFSSL_EC_POINT*)point)) {
        WOLFSSL_MSG("SetECPointInternal error");
        return WOLFSSL_FAILURE;
    }

    return wc_ecc_point_is_on_curve((ecc_point*)point->internal,
        group->curve_idx)
            == MP_OKAY ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}
#endif /* USE_ECC_B_PARAM && (!HAVE_FIPS || HAVE_FIPS_VERSION > 2) */

WOLFSSL_EC_POINT *wolfSSL_EC_POINT_new(const WOLFSSL_EC_GROUP *group)
{
    WOLFSSL_EC_POINT *p;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_new");

    if (group == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_new NULL error");
        return NULL;
    }

    p = (WOLFSSL_EC_POINT *)XMALLOC(sizeof(WOLFSSL_EC_POINT), NULL,
                                    DYNAMIC_TYPE_ECC);
    if (p == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_new malloc ecc point failure");
        return NULL;
    }
    XMEMSET(p, 0, sizeof(WOLFSSL_EC_POINT));

    p->internal = wc_ecc_new_point();
    if (p->internal == NULL) {
        WOLFSSL_MSG("ecc_new_point failure");
        XFREE(p, NULL, DYNAMIC_TYPE_ECC);
        return NULL;
    }

    return p;
}

#if !defined(WOLFSSL_SP_MATH) && !defined(WOLF_CRYPTO_CB_ONLY_ECC)
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_EC_POINT_get_affine_coordinates_GFp(const WOLFSSL_EC_GROUP *group,
                                                const WOLFSSL_EC_POINT *point,
                                                WOLFSSL_BIGNUM *x,
                                                WOLFSSL_BIGNUM *y,
                                                WOLFSSL_BN_CTX *ctx)
{
    mp_digit mp;
#ifdef WOLFSSL_SMALL_STACK
    mp_int* modulus = NULL;
#else
    mp_int modulus[1];
#endif
    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_get_affine_coordinates_GFp");

    if (group == NULL || point == NULL || point->internal == NULL ||
        x == NULL || y == NULL ||
        wolfSSL_EC_POINT_is_at_infinity(group, point)) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_get_affine_coordinates_GFp NULL error");
        return WOLFSSL_FAILURE;
    }

    if (setupPoint(point) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_SMALL_STACK
    modulus = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (modulus == NULL) {
        return WOLFSSL_FAILURE;
    }
#endif

    if (!wolfSSL_BN_is_one(point->Z)) {
        if (mp_init(modulus) != MP_OKAY) {
            WOLFSSL_MSG("mp_init failed");
       #ifdef WOLFSSL_SMALL_STACK
            XFREE(modulus, NULL, DYNAMIC_TYPE_BIGINT);
        #endif
            return WOLFSSL_FAILURE;
        }
        /* Map the Jacobian point back to affine space */
        if (mp_read_radix(modulus, ecc_sets[group->curve_idx].prime,
                MP_RADIX_HEX) != MP_OKAY) {
            WOLFSSL_MSG("mp_read_radix failed");
            mp_clear(modulus);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(modulus, NULL, DYNAMIC_TYPE_BIGINT);
        #endif
            return WOLFSSL_FAILURE;
        }
        if (mp_montgomery_setup(modulus, &mp) != MP_OKAY) {
            WOLFSSL_MSG("mp_montgomery_setup failed");
            mp_clear(modulus);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(modulus, NULL, DYNAMIC_TYPE_BIGINT);
        #endif
            return WOLFSSL_FAILURE;
        }
        if (ecc_map((ecc_point*)point->internal, modulus, mp) != MP_OKAY) {
            WOLFSSL_MSG("ecc_map failed");
            mp_clear(modulus);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(modulus, NULL, DYNAMIC_TYPE_BIGINT);
        #endif
            return WOLFSSL_FAILURE;
        }
        if (SetECPointExternal((WOLFSSL_EC_POINT *)point) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetECPointExternal failed");
            mp_clear(modulus);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(modulus, NULL, DYNAMIC_TYPE_BIGINT);
        #endif
            return WOLFSSL_FAILURE;
        }

        mp_clear(modulus);
    }

    BN_copy(x, point->X);
    BN_copy(y, point->Y);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(modulus, NULL, DYNAMIC_TYPE_BIGINT);
#endif

    return WOLFSSL_SUCCESS;
}
#endif

int wolfSSL_EC_POINT_set_affine_coordinates_GFp(const WOLFSSL_EC_GROUP *group,
                                                WOLFSSL_EC_POINT *point,
                                                const WOLFSSL_BIGNUM *x,
                                                const WOLFSSL_BIGNUM *y,
                                                WOLFSSL_BN_CTX *ctx)
{
    (void)ctx;
    WOLFSSL_ENTER("wolfSSL_EC_POINT_set_affine_coordinates_GFp");

    if (group == NULL || point == NULL || point->internal == NULL ||
        x == NULL || y == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_set_affine_coordinates_GFp NULL error");
        return WOLFSSL_FAILURE;
    }

    if (!point->X) {
        point->X = wolfSSL_BN_new();
    }
    if (!point->Y) {
        point->Y = wolfSSL_BN_new();
    }
    if (!point->Z) {
        point->Z = wolfSSL_BN_new();
    }
    if (!point->X || !point->Y || !point->Z) {
        WOLFSSL_MSG("wolfSSL_BN_new failed");
        return WOLFSSL_FAILURE;
    }

    BN_copy(point->X, x);
    BN_copy(point->Y, y);
    BN_copy(point->Z, wolfSSL_BN_value_one());

    if (SetECPointInternal((WOLFSSL_EC_POINT *)point) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetECPointInternal failed");
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}

#if !defined(WOLFSSL_ATECC508A) && !defined(WOLFSSL_ATECC608A) && \
    !defined(HAVE_SELFTEST) && !defined(WOLFSSL_SP_MATH) && \
    !defined(WOLF_CRYPTO_CB_ONLY_ECC)
int wolfSSL_EC_POINT_add(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *r,
                         const WOLFSSL_EC_POINT *p1,
                         const WOLFSSL_EC_POINT *p2, WOLFSSL_BN_CTX *ctx)
{
#ifdef WOLFSSL_SMALL_STACK
    mp_int* a = NULL;
    mp_int* prime = NULL;
    mp_int* mu = NULL;
#else
    mp_int a[1];
    mp_int prime[1];
    mp_int mu[1];
#endif
    mp_digit mp = 0;
    ecc_point* montP1 = NULL;
    ecc_point* montP2 = NULL;
    ecc_point* eccP1;
    ecc_point* eccP2;
    int ret = WOLFSSL_FAILURE;

    (void)ctx;

    if (!group || !r || !p1 || !p2) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_add error");
        return WOLFSSL_FAILURE;
    }

    if (setupPoint(r) != WOLFSSL_SUCCESS ||
        setupPoint(p1) != WOLFSSL_SUCCESS ||
        setupPoint(p2) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("setupPoint error");
        return WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_SMALL_STACK
    a = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (a == NULL) {
        WOLFSSL_MSG("Failed to allocate memory for mp_int a");
        return WOLFSSL_FAILURE;
    }
    prime = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (prime == NULL) {
        WOLFSSL_MSG("Failed to allocate memory for mp_int prime");
        XFREE(a, NULL, DYNAMIC_TYPE_BIGINT);
        return WOLFSSL_FAILURE;
    }
    mu = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (mu == NULL) {
        WOLFSSL_MSG("Failed to allocate memory for mp_int mu");
        XFREE(a, NULL, DYNAMIC_TYPE_BIGINT);
        XFREE(prime, NULL, DYNAMIC_TYPE_BIGINT);
        return WOLFSSL_FAILURE;
    }
    XMEMSET(a, 0, sizeof(mp_int));
    XMEMSET(prime, 0, sizeof(mp_int));
    XMEMSET(mu, 0, sizeof(mp_int));
#endif

    /* read the curve prime and a */
    if (mp_init_multi(prime, a, mu, NULL, NULL, NULL) != MP_OKAY) {
        WOLFSSL_MSG("mp_init_multi error");
        goto cleanup;
    }

    if (mp_read_radix(a, ecc_sets[group->curve_idx].Af, MP_RADIX_HEX)
            != MP_OKAY) {
        WOLFSSL_MSG("mp_read_radix a error");
        goto cleanup;
    }

    if (mp_read_radix(prime, ecc_sets[group->curve_idx].prime, MP_RADIX_HEX)
            != MP_OKAY) {
        WOLFSSL_MSG("mp_read_radix prime error");
        goto cleanup;
    }

    if (mp_montgomery_setup(prime, &mp) != MP_OKAY) {
        WOLFSSL_MSG("mp_montgomery_setup nqm error");
        goto cleanup;
    }

    eccP1 = (ecc_point*)p1->internal;
    eccP2 = (ecc_point*)p2->internal;

    if (!(montP1 = wc_ecc_new_point_h(NULL)) ||
            !(montP2 = wc_ecc_new_point_h(NULL))) {
        WOLFSSL_MSG("wc_ecc_new_point_h nqm error");
        goto cleanup;
    }

    if ((mp_montgomery_calc_normalization(mu, prime)) != MP_OKAY) {
        WOLFSSL_MSG("mp_montgomery_calc_normalization error");
        goto cleanup;
    }

    /* Convert to Montgomery form */
    if (mp_cmp_d(mu, 1) == MP_EQ) {
        if (wc_ecc_copy_point(eccP1, montP1) != MP_OKAY ||
                wc_ecc_copy_point(eccP2, montP2) != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_copy_point error");
            goto cleanup;
        }
    } else {
        if (mp_mulmod(eccP1->x, mu, prime, montP1->x) != MP_OKAY ||
                mp_mulmod(eccP1->y, mu, prime, montP1->y) != MP_OKAY ||
                mp_mulmod(eccP1->z, mu, prime, montP1->z) != MP_OKAY) {
            WOLFSSL_MSG("mp_mulmod error");
            goto cleanup;
        }
        if (mp_mulmod(eccP2->x, mu, prime, montP2->x) != MP_OKAY ||
                mp_mulmod(eccP2->y, mu, prime, montP2->y) != MP_OKAY ||
                mp_mulmod(eccP2->z, mu, prime, montP2->z) != MP_OKAY) {
            WOLFSSL_MSG("mp_mulmod error");
            goto cleanup;
        }
    }

    if (ecc_projective_add_point(montP1, montP2, (ecc_point*)r->internal,
            a, prime, mp) != MP_OKAY) {
        WOLFSSL_MSG("ecc_projective_add_point error");
        goto cleanup;
    }

    if (ecc_map((ecc_point*)r->internal, prime, mp) != MP_OKAY) {
        WOLFSSL_MSG("ecc_map error");
        goto cleanup;
    }

    ret = WOLFSSL_SUCCESS;
cleanup:
    mp_clear(a);
    mp_clear(prime);
    mp_clear(mu);
    wc_ecc_del_point_h(montP1, NULL);
    wc_ecc_del_point_h(montP2, NULL);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(a, NULL, DYNAMIC_TYPE_BIGINT);
    XFREE(prime, NULL, DYNAMIC_TYPE_BIGINT);
    XFREE(mu, NULL, DYNAMIC_TYPE_BIGINT);
#endif
    return ret;
}

/* Calculate the value: generator * n + q * m
 * return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_EC_POINT_mul(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *r,
                         const WOLFSSL_BIGNUM *n, const WOLFSSL_EC_POINT *q,
                         const WOLFSSL_BIGNUM *m, WOLFSSL_BN_CTX *ctx)
{
#ifdef WOLFSSL_SMALL_STACK
    mp_int* a = NULL;
    mp_int* prime = NULL;
#else
    mp_int a[1], prime[1];
#endif
    int ret = WOLFSSL_FAILURE;
    ecc_point* result = NULL;
    ecc_point* tmp = NULL;

    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_mul");

    if (!group || !r) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_mul NULL error");
        return WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_SMALL_STACK
    a = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (a == NULL)  {
        return WOLFSSL_FAILURE;
    }
    prime = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (prime == NULL)  {
        XFREE(a, NULL, DYNAMIC_TYPE_BIGINT);
        return WOLFSSL_FAILURE;
    }
#endif

    if (!(result = wc_ecc_new_point())) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_new error");
        return WOLFSSL_FAILURE;
    }

    /* read the curve prime and a */
    if (mp_init_multi(prime, a, NULL, NULL, NULL, NULL) != MP_OKAY) {
        WOLFSSL_MSG("mp_init_multi error");
        goto cleanup;
    }

    if (q && setupPoint(q) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("setupPoint error");
        goto cleanup;
    }

    if (mp_read_radix(prime, ecc_sets[group->curve_idx].prime, MP_RADIX_HEX)
            != MP_OKAY) {
        WOLFSSL_MSG("mp_read_radix prime error");
        goto cleanup;
    }

    if (mp_read_radix(a, ecc_sets[group->curve_idx].Af, MP_RADIX_HEX)
            != MP_OKAY) {
        WOLFSSL_MSG("mp_read_radix a error");
        goto cleanup;
    }

    if (n) {
        /* load generator */
    #if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
            (HAVE_FIPS_VERSION>2))
        if (wc_ecc_get_generator(result, group->curve_idx)
                != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_get_generator error");
            goto cleanup;
        }
    #else
        /* wc_ecc_get_generator is not defined in the FIPS v2 module. */
        if (mp_read_radix(result->x, ecc_sets[group->curve_idx].Gx,
                MP_RADIX_HEX) != MP_OKAY) {
            WOLFSSL_MSG("mp_read_radix Gx error");
            goto cleanup;
        }
        if (mp_read_radix(result->y, ecc_sets[group->curve_idx].Gy,
                MP_RADIX_HEX) != MP_OKAY) {
            WOLFSSL_MSG("mp_read_radix Gy error");
            goto cleanup;
        }
        if (mp_set(result->z, 1) != MP_OKAY) {
            WOLFSSL_MSG("mp_set Gz error");
            goto cleanup;
        }
    #endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
    }

    if (n && q && m) {
        /* r = generator * n + q * m */
#ifdef ECC_SHAMIR
        if (ecc_mul2add(result, (mp_int*)n->internal,
                        (ecc_point*)q->internal, (mp_int*)m->internal,
                        result, a, prime, NULL)
                != MP_OKAY) {
            WOLFSSL_MSG("ecc_mul2add error");
            goto cleanup;
        }
#else
        mp_digit mp = 0;
        if (mp_montgomery_setup(prime, &mp) != MP_OKAY) {
            WOLFSSL_MSG("mp_montgomery_setup nqm error");
            goto cleanup;
        }
        if (!(tmp = wc_ecc_new_point())) {
            WOLFSSL_MSG("wolfSSL_EC_POINT_new nqm error");
            goto cleanup;
        }
        /* r = generator * n */
        if (wc_ecc_mulmod((mp_int*)n->internal, result, result, a, prime, 0)
                != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_mulmod nqm error");
            goto cleanup;
        }
        /* tmp = q * m */
        if (wc_ecc_mulmod((mp_int*)m->internal, (ecc_point*)q->internal,
                tmp, a, prime, 0) != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_mulmod nqm error");
            goto cleanup;
        }
        /* result = result + tmp */
        if (ecc_projective_add_point(tmp, result, result, a, prime, mp)
                != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_mulmod nqm error");
            goto cleanup;
        }
        if (ecc_map(result, prime, mp) != MP_OKAY) {
            WOLFSSL_MSG("ecc_map nqm error");
            goto cleanup;
        }
#endif
    }
    else if (n) {
        /* r = generator * n */
        if (wc_ecc_mulmod((mp_int*)n->internal, result, result, a, prime, 1)
                != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_mulmod gn error");
            goto cleanup;
        }
    }
    else if (q && m) {
        /* r = q * m */
        if (wc_ecc_mulmod((mp_int*)m->internal, (ecc_point*)q->internal,
                           result, a, prime, 1) != MP_OKAY) {
            WOLFSSL_MSG("wc_ecc_mulmod qm error");
            goto cleanup;
        }
    }

    /* copy to destination */
    if (wc_ecc_copy_point(result, (ecc_point*)r->internal)) {
        WOLFSSL_MSG("wc_ecc_copy_point error");
        goto cleanup;
    }
    r->inSet = 1;
    if (SetECPointExternal(r) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetECPointExternal error");
        goto cleanup;
    }

    ret = WOLFSSL_SUCCESS;
cleanup:
    mp_clear(a);
    mp_clear(prime);
    wc_ecc_del_point(result);
    wc_ecc_del_point(tmp);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(a, NULL, DYNAMIC_TYPE_BIGINT);
    XFREE(prime, NULL, DYNAMIC_TYPE_BIGINT);
#endif
    return ret;
}
#endif /* !WOLFSSL_ATECC508A && !WOLFSSL_ATECC608A && !HAVE_SELFTEST &&
        * !WOLFSSL_SP_MATH */

/* (x, y) -> (x, -y) */
int wolfSSL_EC_POINT_invert(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *a,
                            WOLFSSL_BN_CTX *ctx)
{
    ecc_point* p;
#ifdef WOLFSSL_SMALL_STACK
    mp_int* prime = NULL;
#else
    mp_int prime[1];
#endif

    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_invert");

    if (!group || !a || !a->internal || setupPoint(a) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    p = (ecc_point*)a->internal;

#ifdef WOLFSSL_SMALL_STACK
    prime = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (prime == NULL) {
        return WOLFSSL_FAILURE;
    }
#endif

    /* read the curve prime and a */
    if (mp_init_multi(prime, NULL, NULL, NULL, NULL, NULL) != MP_OKAY) {
        WOLFSSL_MSG("mp_init_multi error");
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(prime, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
        return WOLFSSL_FAILURE;
    }

    if (mp_sub(prime, p->y, p->y) != MP_OKAY) {
        WOLFSSL_MSG("mp_sub error");
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(prime, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
        return WOLFSSL_FAILURE;
    }

    if (SetECPointExternal(a) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetECPointExternal error");
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(prime, NULL, DYNAMIC_TYPE_BIGINT);
    #endif
        return WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(prime, NULL, DYNAMIC_TYPE_BIGINT);
#endif

    return WOLFSSL_SUCCESS;
}

void wolfSSL_EC_POINT_clear_free(WOLFSSL_EC_POINT *p)
{
    WOLFSSL_ENTER("wolfSSL_EC_POINT_clear_free");

    wolfSSL_EC_POINT_free(p);
}

/* return code compliant with OpenSSL :
 *   0 if equal, 1 if not and -1 in case of error
 */
int wolfSSL_EC_POINT_cmp(const WOLFSSL_EC_GROUP *group,
                         const WOLFSSL_EC_POINT *a, const WOLFSSL_EC_POINT *b,
                         WOLFSSL_BN_CTX *ctx)
{
    int ret;

    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_cmp");

    if (group == NULL || a == NULL || a->internal == NULL || b == NULL ||
        b->internal == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_cmp Bad arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    ret = wc_ecc_cmp_point((ecc_point*)a->internal, (ecc_point*)b->internal);
    if (ret == MP_EQ)
        return 0;
    else if (ret == MP_LT || ret == MP_GT)
        return 1;

    return WOLFSSL_FATAL_ERROR;
}

int wolfSSL_EC_POINT_copy(WOLFSSL_EC_POINT *dest, const WOLFSSL_EC_POINT *src)
{
    WOLFSSL_ENTER("wolfSSL_EC_POINT_copy");

    if (!dest || !src) {
        return WOLFSSL_FAILURE;
    }

    if (setupPoint(src) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    if (wc_ecc_copy_point((ecc_point*) dest->internal,
                          (ecc_point*) src->internal) != MP_OKAY) {
        return WOLFSSL_FAILURE;
    }

    dest->inSet = 1;

    if (SetECPointExternal(dest) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
void wolfSSL_EC_POINT_free(WOLFSSL_EC_POINT *p)
{
    WOLFSSL_ENTER("wolfSSL_EC_POINT_free");

    if (p != NULL) {
        if (p->internal != NULL) {
            wc_ecc_del_point((ecc_point*)p->internal);
            p->internal = NULL;
        }

        wolfSSL_BN_free(p->X);
        wolfSSL_BN_free(p->Y);
        wolfSSL_BN_free(p->Z);
        p->X = NULL;
        p->Y = NULL;
        p->Z = NULL;
        p->inSet = p->exSet = 0;

        XFREE(p, NULL, DYNAMIC_TYPE_ECC);
        /* p = NULL, don't try to access or double free it */
    }
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA
/* return code compliant with OpenSSL :
 *   1 if point at infinity, 0 else
 */
int wolfSSL_EC_POINT_is_at_infinity(const WOLFSSL_EC_GROUP *group,
                                    const WOLFSSL_EC_POINT *point)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_EC_POINT_is_at_infinity");

    if (group == NULL || point == NULL || point->internal == NULL) {
        WOLFSSL_MSG("wolfSSL_EC_POINT_is_at_infinity NULL error");
        return WOLFSSL_FAILURE;
    }

    if (setupPoint(point) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }
    #ifndef WOLF_CRYPTO_CB_ONLY_ECC
    ret = wc_ecc_point_is_at_infinity((ecc_point*)point->internal);
    if (ret < 0) {
        WOLFSSL_MSG("ecc_point_is_at_infinity failure");
        return WOLFSSL_FAILURE;
    }
    #else
        WOLFSSL_MSG("ecc_point_is_at_infinitiy compiled out");
        return WOLFSSL_FAILURE;
    #endif
    return ret;
}

/* End EC_POINT */

#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
size_t wolfSSL_EC_get_builtin_curves(WOLFSSL_EC_BUILTIN_CURVE *r, size_t nitems)
{
    size_t i, min_nitems;
#ifdef HAVE_SELFTEST
    size_t ecc_sets_count;
    for (i = 0; ecc_sets[i].size != 0 && ecc_sets[i].name != NULL; i++);
    ecc_sets_count = i;
#endif

    if (r == NULL || nitems == 0)
        return ecc_sets_count;

    min_nitems = nitems < ecc_sets_count ? nitems : ecc_sets_count;

    for (i = 0; i < min_nitems; i++) {
        r[i].nid = EccEnumToNID(ecc_sets[i].id);
        r[i].comment = wolfSSL_OBJ_nid2sn(r[i].nid);
    }

    return min_nitems;
}
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */

/* Start ECDSA_SIG */
void wolfSSL_ECDSA_SIG_free(WOLFSSL_ECDSA_SIG *sig)
{
    WOLFSSL_ENTER("wolfSSL_ECDSA_SIG_free");

    if (sig) {
        wolfSSL_BN_free(sig->r);
        wolfSSL_BN_free(sig->s);

        XFREE(sig, NULL, DYNAMIC_TYPE_ECC);
    }
}

WOLFSSL_ECDSA_SIG *wolfSSL_ECDSA_SIG_new(void)
{
    WOLFSSL_ECDSA_SIG *sig;

    WOLFSSL_ENTER("wolfSSL_ECDSA_SIG_new");

    sig = (WOLFSSL_ECDSA_SIG*) XMALLOC(sizeof(WOLFSSL_ECDSA_SIG), NULL,
                                       DYNAMIC_TYPE_ECC);
    if (sig == NULL) {
        WOLFSSL_MSG("wolfSSL_ECDSA_SIG_new malloc ECDSA signature failure");
        return NULL;
    }

    sig->s = NULL;
    sig->r = wolfSSL_BN_new();
    if (sig->r == NULL) {
        WOLFSSL_MSG("wolfSSL_ECDSA_SIG_new malloc ECDSA r failure");
        wolfSSL_ECDSA_SIG_free(sig);
        return NULL;
    }

    sig->s = wolfSSL_BN_new();
    if (sig->s == NULL) {
        WOLFSSL_MSG("wolfSSL_ECDSA_SIG_new malloc ECDSA s failure");
        wolfSSL_ECDSA_SIG_free(sig);
        return NULL;
    }

    return sig;
}

void wolfSSL_ECDSA_SIG_get0(const WOLFSSL_ECDSA_SIG* sig,
    const WOLFSSL_BIGNUM** r, const WOLFSSL_BIGNUM** s)
{
    if (sig == NULL) {
        return;
    }

    if (r != NULL) {
        *r = sig->r;
    }
    if (s != NULL) {
        *s = sig->s;
    }
}

int wolfSSL_ECDSA_SIG_set0(WOLFSSL_ECDSA_SIG* sig, WOLFSSL_BIGNUM* r,
    WOLFSSL_BIGNUM* s)
{
    if (sig == NULL || r == NULL || s == NULL) {
        return WOLFSSL_FAILURE;
    }

    wolfSSL_BN_free(sig->r);
    wolfSSL_BN_free(sig->s);

    sig->r = r;
    sig->s = s;

    return WOLFSSL_SUCCESS;
}

/* return signature structure on success, NULL otherwise */
WOLFSSL_ECDSA_SIG *wolfSSL_ECDSA_do_sign(const unsigned char *d, int dlen,
                                         WOLFSSL_EC_KEY *key)
{
    WOLFSSL_ECDSA_SIG *sig = NULL;
    int     initTmpRng = 0;
    WC_RNG* rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRNG = NULL;
    byte*   out = NULL;
    mp_int* sig_r = NULL;
    mp_int* sig_s = NULL;
#else
    WC_RNG  tmpRNG[1];
    byte    out[ECC_BUFSIZE];
    mp_int sig_r[1], sig_s[1];
#endif
    word32 outlen = ECC_BUFSIZE;

    WOLFSSL_ENTER("wolfSSL_ECDSA_do_sign");

    if (d == NULL || key == NULL || key->internal == NULL) {
        WOLFSSL_MSG("wolfSSL_ECDSA_do_sign Bad arguments");
        return NULL;
    }

    /* set internal key if not done */
    if (key->inSet == 0)
    {
        WOLFSSL_MSG("wolfSSL_ECDSA_do_sign No EC key internal set, do it");

        if (SetECKeyInternal(key) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_ECDSA_do_sign SetECKeyInternal failed");
            return NULL;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    tmpRNG = (WC_RNG*)XMALLOC(sizeof(WC_RNG), NULL, DYNAMIC_TYPE_RNG);
    if (tmpRNG == NULL)
        return NULL;
    out = (byte*)XMALLOC(outlen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (out == NULL) {
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
        return NULL;
    }
    sig_r = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (sig_r == NULL) {
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
        return NULL;
    }
    sig_s = (mp_int*)XMALLOC(sizeof(mp_int), NULL, DYNAMIC_TYPE_BIGINT);
    if (sig_s == NULL) {
        XFREE(sig_r, NULL, DYNAMIC_TYPE_BIGINT);
        XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
        return NULL;
    }
#endif

    if (wc_InitRng(tmpRNG) == 0) {
        rng = tmpRNG;
        initTmpRng = 1;
    }
    else {
        WOLFSSL_MSG("wolfSSL_ECDSA_do_sign Bad RNG Init, trying global");
        rng = wolfssl_get_global_rng();
    }

    if (rng) {
        /* use wc_ecc_sign_hash because it supports crypto callbacks */
        if (wc_ecc_sign_hash(d, dlen, out, &outlen, rng,
                                                (ecc_key*)key->internal) == 0) {
            if (mp_init_multi(sig_r, sig_s, NULL, NULL, NULL, NULL) == MP_OKAY) {
               /* put signature blob in ECDSA structure */
                if (DecodeECC_DSA_Sig(out, outlen, sig_r, sig_s) == 0) {
                    sig = wolfSSL_ECDSA_SIG_new();
                    if (sig == NULL) {
                        WOLFSSL_MSG("wolfSSL_ECDSA_SIG_new failed");
                    }
                    else if (SetIndividualExternal(&sig->r, sig_r)
                            != WOLFSSL_SUCCESS) {
                        WOLFSSL_MSG("ecdsa r key error");
                        wolfSSL_ECDSA_SIG_free(sig);
                        sig = NULL;
                    }
                    else if (SetIndividualExternal(&sig->s, sig_s)
                            != WOLFSSL_SUCCESS) {
                        WOLFSSL_MSG("ecdsa s key error");
                        wolfSSL_ECDSA_SIG_free(sig);
                        sig = NULL;
                    }
                }
                mp_free(sig_r);
                mp_free(sig_s);
            }
        }
        else {
            WOLFSSL_MSG("wc_ecc_sign_hash_ex failed");
        }
    }

    if (initTmpRng)
        wc_FreeRng(tmpRNG);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(sig_s, NULL, DYNAMIC_TYPE_BIGINT);
    XFREE(sig_r, NULL, DYNAMIC_TYPE_BIGINT);
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(tmpRNG, NULL, DYNAMIC_TYPE_RNG);
#endif

    return sig;
}

/* return code compliant with OpenSSL :
 *   1 for a valid signature, 0 for an invalid signature and -1 on error
 */
int wolfSSL_ECDSA_do_verify(const unsigned char *d, int dlen,
                            const WOLFSSL_ECDSA_SIG *sig, WOLFSSL_EC_KEY *key)
{
    int check_sign = 0;
#ifdef WOLF_CRYPTO_CB_ONLY_ECC
    byte signature[ECC_MAX_SIG_SIZE];
    word32 signaturelen = (word32)sizeof(signature);
    char* r;
    char* s;
    int ret = 0;
#endif

    WOLFSSL_ENTER("wolfSSL_ECDSA_do_verify");

    if (d == NULL || sig == NULL || key == NULL || key->internal == NULL) {
        WOLFSSL_MSG("wolfSSL_ECDSA_do_verify Bad arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    /* set internal key if not done */
    if (key->inSet == 0)
    {
        WOLFSSL_MSG("No EC key internal set, do it");

        if (SetECKeyInternal(key) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetECKeyInternal failed");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    #ifndef WOLF_CRYPTO_CB_ONLY_ECC
    if (wc_ecc_verify_hash_ex((mp_int*)sig->r->internal,
                              (mp_int*)sig->s->internal, d, dlen, &check_sign,
                              (ecc_key *)key->internal) != MP_OKAY) {
        WOLFSSL_MSG("wc_ecc_verify_hash failed");
        return WOLFSSL_FATAL_ERROR;
    }
    else if (check_sign == 0) {
        WOLFSSL_MSG("wc_ecc_verify_hash incorrect signature detected");
        return WOLFSSL_FAILURE;
    }
    #else
    /* convert big number to hex */
    r = wolfSSL_BN_bn2hex(sig->r);
    s = wolfSSL_BN_bn2hex(sig->s);
    /* get DER-encoded ECDSA signature */
    ret = wc_ecc_rs_to_sig((const char*)r, (const char*)s,
                                        signature, &signaturelen);
    /* free r and s */
    if (r)
        XFREE(r, NULL, DYNAMIC_TYPE_OPENSSL);
    if (s)
        XFREE(s, NULL, DYNAMIC_TYPE_OPENSSL);

    if (ret != MP_OKAY) {
        WOLFSSL_MSG("wc_ecc_verify_hash failed");
        return WOLFSSL_FATAL_ERROR;
    }
    /* verify hash. expects to call wc_CryptoCb_EccVerify internally */
    ret = wc_ecc_verify_hash(signature, signaturelen, d, dlen, &check_sign,
                        (ecc_key*)key->internal);

    if (ret != MP_OKAY) {
        WOLFSSL_MSG("wc_ecc_verify_hash failed");
        return WOLFSSL_FATAL_ERROR;
    }
    else if (check_sign == 0) {
        WOLFSSL_MSG("wc_ecc_verify_hash incorrect signature detected");
        return WOLFSSL_FAILURE;
    }
    #endif

    return WOLFSSL_SUCCESS;
}

WOLFSSL_ECDSA_SIG *wolfSSL_d2i_ECDSA_SIG(WOLFSSL_ECDSA_SIG **sig,
                                         const unsigned char **pp, long len)
{
    WOLFSSL_ECDSA_SIG *s = NULL;

    if (pp == NULL)
        return NULL;
    if (sig != NULL)
        s = *sig;
    if (s == NULL) {
        s = wolfSSL_ECDSA_SIG_new();
        if (s == NULL)
            return NULL;
    }

    /* DecodeECC_DSA_Sig calls mp_init, so free these */
    mp_free((mp_int*)s->r->internal);
    mp_free((mp_int*)s->s->internal);

    if (DecodeECC_DSA_Sig(*pp, (word32)len, (mp_int*)s->r->internal,
                                          (mp_int*)s->s->internal) != MP_OKAY) {
        if (sig == NULL || *sig == NULL)
            wolfSSL_ECDSA_SIG_free(s);
        return NULL;
    }

    *pp += len;
    if (sig != NULL)
        *sig = s;
    return s;
}

int wolfSSL_i2d_ECDSA_SIG(const WOLFSSL_ECDSA_SIG *sig, unsigned char **pp)
{
    word32 len;

    if (sig == NULL)
        return 0;

    /* ASN.1: SEQ + INT + INT
     *   ASN.1 Integer must be a positive value - prepend zero if number has
     *   top bit set.
     */
    len = 2 + mp_leading_bit((mp_int*)sig->r->internal) +
              mp_unsigned_bin_size((mp_int*)sig->r->internal) +
          2 + mp_leading_bit((mp_int*)sig->s->internal) +
              mp_unsigned_bin_size((mp_int*)sig->s->internal);
    /* Two bytes required for length if ASN.1 SEQ data greater than 127 bytes
     * and less than 256 bytes.
     */
    len = 1 + ((len > 127) ? 2 : 1) + len;
    if (pp != NULL && *pp != NULL) {
        if (StoreECC_DSA_Sig(*pp, &len, (mp_int*)sig->r->internal,
                                        (mp_int*)sig->s->internal) != MP_OKAY) {
            len = 0;
        }
        else
            *pp += len;
    }

    return (int)len;
}
/* End ECDSA_SIG */

#ifndef WOLF_CRYPTO_CB_ONLY_ECC
/* Start ECDH */
/* return code compliant with OpenSSL :
 *   length of computed key if success, -1 if error
 */
int wolfSSL_ECDH_compute_key(void *out, size_t outlen,
                             const WOLFSSL_EC_POINT *pub_key,
                             WOLFSSL_EC_KEY *ecdh,
                             void *(*KDF) (const void *in, size_t inlen,
                                           void *out, size_t *outlen))
{
    word32 len;
    ecc_key* key;
    int ret;
#if defined(ECC_TIMING_RESISTANT) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,0)))
    int setGlobalRNG = 0;
#endif
    (void)KDF;

    WOLFSSL_ENTER("wolfSSL_ECDH_compute_key");

    if (out == NULL || pub_key == NULL || pub_key->internal == NULL ||
        ecdh == NULL || ecdh->internal == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    /* set internal key if not done */
    if (ecdh->inSet == 0)
    {
        WOLFSSL_MSG("No EC key internal set, do it");

        if (SetECKeyInternal(ecdh) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetECKeyInternal failed");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    len = (word32)outlen;
    key = (ecc_key*)ecdh->internal;

#if defined(ECC_TIMING_RESISTANT) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,0)))
    if (key->rng == NULL) {
        if ((key->rng = wolfssl_get_global_rng()) == NULL) {
            if (wolfSSL_RAND_Init() != WOLFSSL_SUCCESS) {
                WOLFSSL_MSG("No RNG to use");
                return WOLFSSL_FATAL_ERROR;
            }
            key->rng = wolfssl_get_global_rng();
        }
        setGlobalRNG = 1;
    }
#endif
    PRIVATE_KEY_UNLOCK();
    ret = wc_ecc_shared_secret_ssh(key, (ecc_point*)pub_key->internal,
            (byte *)out, &len);
    PRIVATE_KEY_LOCK();
#if defined(ECC_TIMING_RESISTANT) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,0)))
    if (setGlobalRNG)
        key->rng = NULL;
#endif
    if (ret != MP_OKAY) {
        WOLFSSL_MSG("wc_ecc_shared_secret failed");
        return WOLFSSL_FATAL_ERROR;
    }

    return len;
}
#endif /* WOLF_CRYPTO_CB_ONLY_ECC */
/* End ECDH */
#if !defined(NO_FILESYSTEM)

#ifndef NO_BIO

#ifdef WOLFSSL_KEY_GEN
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_PEM_write_EC_PUBKEY(XFILE fp, WOLFSSL_EC_KEY* key)
{
    int ret = WOLFSSL_SUCCESS;
    WOLFSSL_BIO* bio = NULL;

    WOLFSSL_ENTER("wolfSSL_PEM_write_EC_PUBKEY");

    if (fp == XBADFILE || key == NULL) {
        WOLFSSL_MSG("Bad argument.");
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bio == NULL) {
            WOLFSSL_MSG("wolfSSL_BIO_new failed.");
            ret = WOLFSSL_FAILURE;
        }
        else if (wolfSSL_BIO_set_fp(bio, fp, BIO_NOCLOSE) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_BIO_set_fp failed.");
            ret = WOLFSSL_FAILURE;
        }
    }
    if (ret == WOLFSSL_SUCCESS && wolfSSL_PEM_write_bio_EC_PUBKEY(bio, key)
        != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_PEM_write_bio_EC_PUBKEY failed.");
        ret = WOLFSSL_FAILURE;
    }

    if (bio != NULL) {
        wolfSSL_BIO_free(bio);
    }

    WOLFSSL_LEAVE("wolfSSL_PEM_write_EC_PUBKEY", ret);

    return ret;
}
#endif

/* Uses the same format of input as wolfSSL_PEM_read_bio_PrivateKey but expects
 * the results to be an EC key.
 *
 * bio  structure to read EC private key from
 * ec   if not null is then set to the result
 * cb   password callback for reading PEM
 * pass password string
 *
 * returns a pointer to a new WOLFSSL_EC_KEY struct on success and NULL on fail
 */

WOLFSSL_EC_KEY* wolfSSL_PEM_read_bio_EC_PUBKEY(WOLFSSL_BIO* bio,
                                               WOLFSSL_EC_KEY** ec,
                                               wc_pem_password_cb* cb,
                                               void *pass)
{
    WOLFSSL_EVP_PKEY* pkey;
    WOLFSSL_EC_KEY* local;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_EC_PUBKEY");

    pkey = wolfSSL_PEM_read_bio_PUBKEY(bio, NULL, cb, pass);
    if (pkey == NULL) {
        return NULL;
    }

    /* Since the WOLFSSL_EC_KEY structure is being taken from WOLFSSL_EVP_PKEY the
     * flag indicating that the WOLFSSL_EC_KEY structure is owned should be FALSE
     * flag indicating that the WOLFSSL_EC_KEY structure is owned should be FALSE
     * to avoid having it free'd */
    pkey->ownEcc = 0;
    local = pkey->ecc;
    if (ec != NULL) {
        *ec = local;
    }

    wolfSSL_EVP_PKEY_free(pkey);
    return local;
}

/* Reads a private EC key from a WOLFSSL_BIO into a WOLFSSL_EC_KEY.
 * Returns WOLFSSL_SUCCESS or WOLFSSL_FAILURE
 */
WOLFSSL_EC_KEY* wolfSSL_PEM_read_bio_ECPrivateKey(WOLFSSL_BIO* bio,
                                                  WOLFSSL_EC_KEY** ec,
                                                  wc_pem_password_cb* cb,
                                                  void *pass)
{
    WOLFSSL_EVP_PKEY* pkey;
    WOLFSSL_EC_KEY* local;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_ECPrivateKey");

    pkey = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL, cb, pass);
    if (pkey == NULL) {
        return NULL;
    }

    /* Since the WOLFSSL_EC_KEY structure is being taken from WOLFSSL_EVP_PKEY the
     * flag indicating that the WOLFSSL_EC_KEY structure is owned should be FALSE
     * to avoid having it free'd */
    pkey->ownEcc = 0;
    local = pkey->ecc;
    if (ec != NULL) {
        *ec = local;
    }

    wolfSSL_EVP_PKEY_free(pkey);
    return local;
}
#endif /* !NO_BIO */
#endif /* NO_FILESYSTEM */

#if defined(WOLFSSL_KEY_GEN)
#ifndef NO_BIO
/* Takes a public WOLFSSL_EC_KEY and writes it out to WOLFSSL_BIO
 * Returns WOLFSSL_SUCCESS or WOLFSSL_FAILURE
 */
int wolfSSL_PEM_write_bio_EC_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_EC_KEY* ec)
{
    int ret = 0;
    WOLFSSL_EVP_PKEY* pkey;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_EC_PUBKEY");

    if (bio == NULL || ec == NULL) {
        WOLFSSL_MSG("Bad Function Arguments");
        return WOLFSSL_FAILURE;
    }

    /* Initialize pkey structure */
    pkey = wolfSSL_EVP_PKEY_new_ex(bio->heap);
    if (pkey == NULL) {
        WOLFSSL_MSG("wolfSSL_EVP_PKEY_new_ex failed");
        return WOLFSSL_FAILURE;
    }

    /* Set pkey info */
    pkey->ecc    = ec;
    pkey->ownEcc = 0; /* pkey does not own ECC */
    pkey->type = EVP_PKEY_EC;

    if ((ret = WriteBioPUBKEY(bio, pkey)) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_PEM_write_bio_PUBKEY failed");
    }
    wolfSSL_EVP_PKEY_free(pkey);

    return ret;
}

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_PEM_write_bio_ECPrivateKey(WOLFSSL_BIO* bio, WOLFSSL_EC_KEY* ec,
                                       const EVP_CIPHER* cipher,
                                       unsigned char* passwd, int len,
                                       wc_pem_password_cb* cb, void* arg)
{
    int ret = 0, der_max_len = 0, derSz = 0;
    byte *derBuf;
    WOLFSSL_EVP_PKEY* pkey;
    WOLFSSL_ENTER("WOLFSSL_PEM_write_bio_ECPrivateKey");

    if (bio == NULL || ec == NULL) {
        WOLFSSL_MSG("Bad Function Arguments");
        return WOLFSSL_FAILURE;
    }

    /* Initialize pkey structure */
    pkey = wolfSSL_EVP_PKEY_new_ex(bio->heap);
    if (pkey == NULL) {
        WOLFSSL_MSG("wolfSSL_EVP_PKEY_new_ex failed");
        return WOLFSSL_FAILURE;
    }

    /* Set pkey info */
    pkey->ecc    = ec;
    pkey->ownEcc = 0; /* pkey does not own ECC */
    pkey->type = EVP_PKEY_EC;

    /* 4 > size of pub, priv + ASN.1 additional informations
     */
    der_max_len = 4 * wc_ecc_size((ecc_key*)ec->internal) + AES_BLOCK_SIZE;

    derBuf = (byte*)XMALLOC(der_max_len, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (derBuf == NULL) {
        WOLFSSL_MSG("Malloc failed");
        wolfSSL_EVP_PKEY_free(pkey);
        return WOLFSSL_FAILURE;
    }

    /* convert key to der format */
    derSz = wc_EccKeyToDer((ecc_key*)ec->internal, derBuf, der_max_len);
    if (derSz < 0) {
        WOLFSSL_MSG("wc_EccKeyToDer failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        wolfSSL_EVP_PKEY_free(pkey);
        return WOLFSSL_FAILURE;
    }

    pkey->pkey.ptr = (char*)XMALLOC(derSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (pkey->pkey.ptr == NULL) {
        WOLFSSL_MSG("key malloc failed");
        XFREE(derBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
        wolfSSL_EVP_PKEY_free(pkey);
        return WOLFSSL_FAILURE;
    }

    /* add der info to the evp key */
    pkey->pkey_sz = derSz;
    XMEMCPY(pkey->pkey.ptr, derBuf, derSz);
    XFREE(derBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);

    ret = wolfSSL_PEM_write_bio_PrivateKey(bio, pkey, cipher, passwd, len,
                                        cb, arg);
    wolfSSL_EVP_PKEY_free(pkey);

    return ret;
}

#endif /* !NO_BIO */

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_PEM_write_mem_ECPrivateKey(WOLFSSL_EC_KEY* ecc,
                                       const EVP_CIPHER* cipher,
                                       unsigned char* passwd, int passwdSz,
                                       unsigned char **pem, int *plen)
{
#if defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)
    byte *derBuf, *tmp, *cipherInfo = NULL;
    int  der_max_len = 0, derSz = 0;
    const int type = ECC_PRIVATEKEY_TYPE;
    const char* header = NULL;
    const char* footer = NULL;

    WOLFSSL_MSG("wolfSSL_PEM_write_mem_ECPrivateKey");
    if (pem == NULL || plen == NULL || ecc == NULL || ecc->internal == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    if (wc_PemGetHeaderFooter(type, &header, &footer) != 0)
        return WOLFSSL_FAILURE;

    if (ecc->inSet == 0) {
        WOLFSSL_MSG("No ECC internal set, do it");

        if (SetECKeyInternal(ecc) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("SetECKeyInternal failed");
            return WOLFSSL_FAILURE;
        }
    }

    /* 4 > size of pub, priv + ASN.1 additional information */
    der_max_len = 4 * wc_ecc_size((ecc_key*)ecc->internal) + AES_BLOCK_SIZE;

    derBuf = (byte*)XMALLOC(der_max_len, NULL, DYNAMIC_TYPE_DER);
    if (derBuf == NULL) {
        WOLFSSL_MSG("malloc failed");
        return WOLFSSL_FAILURE;
    }

    /* Key to DER */
    derSz = wc_EccKeyToDer((ecc_key*)ecc->internal, derBuf, der_max_len);
    if (derSz < 0) {
        WOLFSSL_MSG("wc_EccKeyToDer failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        return WOLFSSL_FAILURE;
    }

    /* encrypt DER buffer if required */
    if (passwd != NULL && passwdSz > 0 && cipher != NULL) {
        int ret;

        ret = EncryptDerKey(derBuf, &derSz, cipher,
                            passwd, passwdSz, &cipherInfo, der_max_len);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("EncryptDerKey failed");
            XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
            return ret;
        }

        /* tmp buffer with a max size */
        *plen = (derSz * 2) + (int)XSTRLEN(header) + 1 +
            (int)XSTRLEN(footer) + 1 + HEADER_ENCRYPTED_KEY_SIZE;
    }
    else { /* tmp buffer with a max size */
        *plen = (derSz * 2) + (int)XSTRLEN(header) + 1 +
            (int)XSTRLEN(footer) + 1;
    }

    tmp = (byte*)XMALLOC(*plen, NULL, DYNAMIC_TYPE_PEM);
    if (tmp == NULL) {
        WOLFSSL_MSG("malloc failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        if (cipherInfo != NULL)
            XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);
        return WOLFSSL_FAILURE;
    }

    /* DER to PEM */
    *plen = wc_DerToPemEx(derBuf, derSz, tmp, *plen, cipherInfo, type);
    if (*plen <= 0) {
        WOLFSSL_MSG("wc_DerToPemEx failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        if (cipherInfo != NULL)
            XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);
        return WOLFSSL_FAILURE;
    }
    XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
    if (cipherInfo != NULL)
        XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);

    *pem = (byte*)XMALLOC((*plen)+1, NULL, DYNAMIC_TYPE_KEY);
    if (*pem == NULL) {
        WOLFSSL_MSG("malloc failed");
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        return WOLFSSL_FAILURE;
    }
    XMEMSET(*pem, 0, (*plen)+1);

    if (XMEMCPY(*pem, tmp, *plen) == NULL) {
        WOLFSSL_MSG("XMEMCPY failed");
        XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        return WOLFSSL_FAILURE;
    }
    XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);

    return WOLFSSL_SUCCESS;
#else
    (void)ecc;
    (void)cipher;
    (void)passwd;
    (void)passwdSz;
    (void)pem;
    (void)plen;
    return WOLFSSL_FAILURE;
#endif /* WOLFSSL_PEM_TO_DER || WOLFSSL_DER_TO_PEM */
}

#ifndef NO_FILESYSTEM
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_PEM_write_ECPrivateKey(XFILE fp, WOLFSSL_EC_KEY *ecc,
                                   const EVP_CIPHER *enc,
                                   unsigned char *kstr, int klen,
                                   wc_pem_password_cb *cb, void *u)
{
    byte *pem;
    int  plen, ret;

    (void)cb;
    (void)u;

    WOLFSSL_MSG("wolfSSL_PEM_write_ECPrivateKey");

    if (fp == XBADFILE || ecc == NULL || ecc->internal == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    ret = wolfSSL_PEM_write_mem_ECPrivateKey(ecc, enc, kstr, klen, &pem, &plen);
    if (ret != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_PEM_write_mem_ECPrivateKey failed");
        return WOLFSSL_FAILURE;
    }

    ret = (int)XFWRITE(pem, plen, 1, fp);
    if (ret != 1) {
        WOLFSSL_MSG("ECC private key file write failed");
        return WOLFSSL_FAILURE;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    return WOLFSSL_SUCCESS;
}

#endif /* NO_FILESYSTEM */
#endif /* defined(WOLFSSL_KEY_GEN) */

#ifndef NO_BIO

/* returns a new WOLFSSL_EC_GROUP structure on success and NULL on fail */
WOLFSSL_EC_GROUP* wolfSSL_PEM_read_bio_ECPKParameters(WOLFSSL_BIO* bio,
        WOLFSSL_EC_GROUP** group, wc_pem_password_cb* cb, void* pass)
{
    WOLFSSL_EVP_PKEY* pkey;
    WOLFSSL_EC_GROUP* ret = NULL;

    /* check on if bio is null is done in wolfSSL_PEM_read_bio_PrivateKey */
    pkey = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL, cb, pass);
    if (pkey != NULL) {
        if (pkey->type != EVP_PKEY_EC) {
            WOLFSSL_MSG("Unexpected key type");
        }
        else {
            ret = (WOLFSSL_EC_GROUP*)wolfSSL_EC_KEY_get0_group(pkey->ecc);

            /* set ecc group to null so it is not free'd when pkey is free'd */
            pkey->ecc->group = NULL;
        }
    }

    (void)group;
    wolfSSL_EVP_PKEY_free(pkey);
    return ret;
}

#endif /* !NO_BIO */

/* return WOLFSSL_SUCCESS if success, WOLFSSL_FATAL_ERROR if error */
int wolfSSL_EC_KEY_LoadDer(WOLFSSL_EC_KEY* key, const unsigned char* derBuf,
                           int derSz)
{
    return wolfSSL_EC_KEY_LoadDer_ex(key, derBuf, derSz,
                                     WOLFSSL_EC_KEY_LOAD_PRIVATE);
}

int wolfSSL_EC_KEY_LoadDer_ex(WOLFSSL_EC_KEY* key, const unsigned char* derBuf,
                              int derSz, int opt)
{
    int ret;
    word32 idx = 0;
    word32 algId;

    WOLFSSL_ENTER("wolfSSL_EC_KEY_LoadDer");

    if (key == NULL || key->internal == NULL || derBuf == NULL || derSz <= 0) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    key->pkcs8HeaderSz = 0;

    /* Check if input buffer has PKCS8 header. In the case that it does not
     * have a PKCS8 header then do not error out. */
    if ((ret = ToTraditionalInline_ex((const byte*)derBuf, &idx, (word32)derSz,
                                                                 &algId)) > 0) {
        WOLFSSL_MSG("Found PKCS8 header");
        key->pkcs8HeaderSz = (word16)idx;
    }
    else {
        if (ret != ASN_PARSE_E) {
            WOLFSSL_MSG("Unexpected error with trying to remove PKCS8 header");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    if (opt == WOLFSSL_EC_KEY_LOAD_PRIVATE) {
        ret = wc_EccPrivateKeyDecode(derBuf, &idx, (ecc_key*)key->internal,
                                     derSz);
    }
    else {
        ret = wc_EccPublicKeyDecode(derBuf, &idx, (ecc_key*)key->internal,
                                    derSz);
    }
    if (ret < 0) {
        if (opt == WOLFSSL_EC_KEY_LOAD_PRIVATE) {
            WOLFSSL_MSG("wc_EccPrivateKeyDecode failed");
        }
        else {
            WOLFSSL_MSG("wc_EccPublicKeyDecode failed");
        }
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetECKeyExternal(key) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("SetECKeyExternal failed");
        return WOLFSSL_FATAL_ERROR;
    }

    key->inSet = 1;

    return WOLFSSL_SUCCESS;
}

#endif /* OPENSSL_EXTRA */

#endif /* HAVE_ECC */

/*******************************************************************************
 * END OF EC API
 ******************************************************************************/

#endif /* !WOLFSSL_PK_INCLUDED */

