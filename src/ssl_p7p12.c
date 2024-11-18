/* ssl_p7p12.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(OPENSSL_EXTRA) && (defined(HAVE_FIPS) || defined(HAVE_SELFTEST))
    #include <wolfssl/wolfcrypt/pkcs7.h>
#endif
#if defined(OPENSSL_ALL) && defined(HAVE_PKCS7)
    #include <wolfssl/openssl/pkcs7.h>
#endif

#if !defined(WOLFSSL_SSL_P7P12_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_p7p12.c does not need to be compiled separately from ssl.c
    #endif
#else

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS)

/*******************************************************************************
 * START OF PKCS7 APIs
 ******************************************************************************/
#ifdef HAVE_PKCS7

#ifdef OPENSSL_ALL
PKCS7* wolfSSL_PKCS7_new(void)
{
    WOLFSSL_PKCS7* pkcs7;
    int ret = 0;

    pkcs7 = (WOLFSSL_PKCS7*)XMALLOC(sizeof(WOLFSSL_PKCS7), NULL,
                                    DYNAMIC_TYPE_PKCS7);
    if (pkcs7 != NULL) {
        XMEMSET(pkcs7, 0, sizeof(WOLFSSL_PKCS7));
        ret = wc_PKCS7_Init(&pkcs7->pkcs7, NULL, INVALID_DEVID);
    }

    if (ret != 0 && pkcs7 != NULL) {
        XFREE(pkcs7, NULL, DYNAMIC_TYPE_PKCS7);
        pkcs7 = NULL;
    }

    return (PKCS7*)pkcs7;
}

/******************************************************************************
* wolfSSL_PKCS7_SIGNED_new - allocates PKCS7 and initialize it for a signed data
*
* RETURNS:
* returns pointer to the PKCS7 structure on success, otherwise returns NULL
*/
PKCS7_SIGNED* wolfSSL_PKCS7_SIGNED_new(void)
{
    byte signedData[]= { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
    PKCS7* pkcs7 = NULL;

    if ((pkcs7 = wolfSSL_PKCS7_new()) == NULL)
        return NULL;
    pkcs7->contentOID = SIGNED_DATA;
    if ((wc_PKCS7_SetContentType(pkcs7, signedData, sizeof(signedData))) < 0) {
        if (pkcs7) {
            wolfSSL_PKCS7_free(pkcs7);
            return NULL;
        }
    }
    return pkcs7;
}

void wolfSSL_PKCS7_free(PKCS7* pkcs7)
{
    WOLFSSL_PKCS7* p7 = (WOLFSSL_PKCS7*)pkcs7;

    if (p7 != NULL) {
        XFREE(p7->data, NULL, DYNAMIC_TYPE_PKCS7);
        wc_PKCS7_Free(&p7->pkcs7);
        if (p7->certs)
            wolfSSL_sk_pop_free(p7->certs, NULL);
        XFREE(p7, NULL, DYNAMIC_TYPE_PKCS7);
    }
}

void wolfSSL_PKCS7_SIGNED_free(PKCS7_SIGNED* p7)
{
    wolfSSL_PKCS7_free(p7);
    return;
}

/**
 * Convert DER/ASN.1 encoded signedData structure to internal PKCS7
 * structure. Note, does not support detached content.
 *
 * p7 - pointer to set to address of newly created PKCS7 structure on return
 * in - pointer to pointer of DER/ASN.1 data
 * len - length of input data, bytes
 *
 * Returns newly allocated and populated PKCS7 structure or NULL on error.
 */
PKCS7* wolfSSL_d2i_PKCS7(PKCS7** p7, const unsigned char** in, int len)
{
    return wolfSSL_d2i_PKCS7_ex(p7, in, len, NULL, 0);
}

/* This internal function is only decoding and setting up the PKCS7 struct. It
* does not verify the PKCS7 signature.
*
* RETURNS:
* returns pointer to a PKCS7 structure on success, otherwise returns NULL
*/
static PKCS7* wolfSSL_d2i_PKCS7_only(PKCS7** p7, const unsigned char** in,
    int len, byte* content, word32 contentSz)
{
    WOLFSSL_PKCS7* pkcs7 = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_PKCS7_ex");

    if (in == NULL || *in == NULL || len < 0)
        return NULL;

    if ((pkcs7 = (WOLFSSL_PKCS7*)wolfSSL_PKCS7_new()) == NULL)
        return NULL;

    pkcs7->len = len;
    pkcs7->data = (byte*)XMALLOC(pkcs7->len, NULL, DYNAMIC_TYPE_PKCS7);
    if (pkcs7->data == NULL) {
        wolfSSL_PKCS7_free((PKCS7*)pkcs7);
        return NULL;
    }
    XMEMCPY(pkcs7->data, *in, pkcs7->len);

    if (content != NULL) {
        pkcs7->pkcs7.content = content;
        pkcs7->pkcs7.contentSz = contentSz;
    }

    if (p7 != NULL)
        *p7 = (PKCS7*)pkcs7;
    *in += pkcs7->len;
    return (PKCS7*)pkcs7;
}


/*****************************************************************************
* wolfSSL_d2i_PKCS7_ex - Converts the given unsigned char buffer of size len
* into a PKCS7 object.  Optionally, accepts a byte buffer of content which
* is stored as the PKCS7 object's content, to support detached signatures.
* @param content The content which is signed, in case the signature is
*                detached.  Ignored if NULL.
* @param contentSz The size of the passed in content.
*
* RETURNS:
* returns pointer to a PKCS7 structure on success, otherwise returns NULL
*/
PKCS7* wolfSSL_d2i_PKCS7_ex(PKCS7** p7, const unsigned char** in, int len,
        byte* content, word32 contentSz)
{
    WOLFSSL_PKCS7* pkcs7 = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_PKCS7_ex");

    if (in == NULL || *in == NULL || len < 0)
        return NULL;

    pkcs7 = (WOLFSSL_PKCS7*)wolfSSL_d2i_PKCS7_only(p7, in, len, content,
            contentSz);
    if (pkcs7 != NULL) {
        if (wc_PKCS7_VerifySignedData(&pkcs7->pkcs7, pkcs7->data, pkcs7->len)
                                                                         != 0) {
            WOLFSSL_MSG("wc_PKCS7_VerifySignedData failed");
            wolfSSL_PKCS7_free((PKCS7*)pkcs7);
            if (p7 != NULL) {
                *p7 = NULL;
            }
            return NULL;
        }
    }

    return (PKCS7*)pkcs7;
}


/**
 * This API was added as a helper function for libest. It
 * extracts a stack of certificates from the pkcs7 object.
 * @param pkcs7 PKCS7 parameter object
 * @return WOLFSSL_STACK_OF(WOLFSSL_X509)*
 */
WOLFSSL_STACK* wolfSSL_PKCS7_to_stack(PKCS7* pkcs7)
{
    int i;
    WOLFSSL_PKCS7* p7 = (WOLFSSL_PKCS7*)pkcs7;
    WOLF_STACK_OF(WOLFSSL_X509)* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_PKCS7_to_stack");

    if (!p7) {
        WOLFSSL_MSG("Bad parameter");
        return NULL;
    }

    if (p7->certs)
        return p7->certs;

    for (i = 0; i < MAX_PKCS7_CERTS && p7->pkcs7.cert[i]; i++) {
        WOLFSSL_X509* x509 = wolfSSL_X509_d2i_ex(NULL, p7->pkcs7.cert[i],
            p7->pkcs7.certSz[i], pkcs7->heap);
        if (!ret)
            ret = wolfSSL_sk_X509_new_null();
        if (x509) {
            if (wolfSSL_sk_X509_push(ret, x509) <= 0) {
                wolfSSL_X509_free(x509);
                WOLFSSL_MSG("wolfSSL_sk_X509_push error");
                goto error;
            }
        }
        else {
            WOLFSSL_MSG("wolfSSL_X509_d2i error");
            goto error;
        }
    }

    /* Save stack to free later */
    if (p7->certs)
        wolfSSL_sk_pop_free(p7->certs, NULL);
    p7->certs = ret;

    return ret;
error:
    if (ret) {
        wolfSSL_sk_pop_free(ret, NULL);
    }
    return NULL;
}

/**
 * Return stack of signers contained in PKCS7 cert.
 * Notes:
 * - Currently only PKCS#7 messages with a single signer cert is supported.
 * - Returned WOLFSSL_STACK must be freed by caller.
 *
 * pkcs7 - PKCS7 struct to retrieve signer certs from.
 * certs - currently unused
 * flags - flags to control function behavior.
 *
 * Return WOLFSSL_STACK of signers on success, NULL on error.
 */
WOLFSSL_STACK* wolfSSL_PKCS7_get0_signers(PKCS7* pkcs7, WOLFSSL_STACK* certs,
                                          int flags)
{
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_STACK* signers = NULL;
    WOLFSSL_PKCS7* p7 = (WOLFSSL_PKCS7*)pkcs7;

    if (p7 == NULL)
        return NULL;

    /* Only PKCS#7 messages with a single cert that is the verifying certificate
     * is supported.
     */
    if (flags & PKCS7_NOINTERN) {
        WOLFSSL_MSG("PKCS7_NOINTERN flag not supported");
        return NULL;
    }

    signers = wolfSSL_sk_X509_new_null();
    if (signers == NULL)
        return NULL;

    if (wolfSSL_d2i_X509(&x509, (const byte**)&p7->pkcs7.singleCert,
                         p7->pkcs7.singleCertSz) == NULL) {
        wolfSSL_sk_X509_pop_free(signers, NULL);
        return NULL;
    }

    if (wolfSSL_sk_X509_push(signers, x509) <= 0) {
        wolfSSL_sk_X509_pop_free(signers, NULL);
        return NULL;
    }

    (void)certs;

    return signers;
}

#ifndef NO_BIO

PKCS7* wolfSSL_d2i_PKCS7_bio(WOLFSSL_BIO* bio, PKCS7** p7)
{
    WOLFSSL_PKCS7* pkcs7;
    int ret;

    WOLFSSL_ENTER("wolfSSL_d2i_PKCS7_bio");

    if (bio == NULL)
        return NULL;

    if ((pkcs7 = (WOLFSSL_PKCS7*)wolfSSL_PKCS7_new()) == NULL)
        return NULL;

    pkcs7->len = wolfSSL_BIO_get_len(bio);
    pkcs7->data = (byte*)XMALLOC(pkcs7->len, NULL, DYNAMIC_TYPE_PKCS7);
    if (pkcs7->data == NULL) {
        wolfSSL_PKCS7_free((PKCS7*)pkcs7);
        return NULL;
    }

    if ((ret = wolfSSL_BIO_read(bio, pkcs7->data, pkcs7->len)) <= 0) {
        wolfSSL_PKCS7_free((PKCS7*)pkcs7);
        return NULL;
    }
    /* pkcs7->len may change if using b64 for example */
    pkcs7->len = ret;

    if (wc_PKCS7_VerifySignedData(&pkcs7->pkcs7, pkcs7->data, pkcs7->len)
                                                                         != 0) {
        WOLFSSL_MSG("wc_PKCS7_VerifySignedData failed");
        wolfSSL_PKCS7_free((PKCS7*)pkcs7);
        return NULL;
    }

    if (p7 != NULL)
        *p7 = (PKCS7*)pkcs7;
    return (PKCS7*)pkcs7;
}

int wolfSSL_i2d_PKCS7(PKCS7 *p7, unsigned char **out)
{
    byte* output = NULL;
    int localBuf = 0;
    int len;
    WC_RNG rng;
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    WOLFSSL_ENTER("wolfSSL_i2d_PKCS7");

    if (!out || !p7) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    if (!p7->rng) {
        if (wc_InitRng(&rng) != 0) {
            WOLFSSL_MSG("wc_InitRng error");
            return WOLFSSL_FAILURE;
        }
        p7->rng = &rng; /* cppcheck-suppress autoVariables
                         */
    }

    if ((len = wc_PKCS7_EncodeSignedData(p7, NULL, 0)) < 0) {
        WOLFSSL_MSG("wc_PKCS7_EncodeSignedData error");
        goto cleanup;
    }

    if (*out == NULL) {
        output = (byte*)XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (!output) {
            WOLFSSL_MSG("malloc error");
            goto cleanup;
        }
        localBuf = 1;
    }
    else {
        output = *out;
    }

    if ((len = wc_PKCS7_EncodeSignedData(p7, output, (word32)len)) < 0) {
        WOLFSSL_MSG("wc_PKCS7_EncodeSignedData error");
        goto cleanup;
    }

    ret = len;
cleanup:
    if (p7->rng == &rng) {
        wc_FreeRng(&rng);
        p7->rng = NULL;
    }
    if (ret == WC_NO_ERR_TRACE(WOLFSSL_FAILURE) && localBuf)
        XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret != WC_NO_ERR_TRACE(WOLFSSL_FAILURE))
        *out = output;
    return ret;
}

int wolfSSL_i2d_PKCS7_bio(WOLFSSL_BIO *bio, PKCS7 *p7)
{
    byte* output = NULL;
    int len;
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    WOLFSSL_ENTER("wolfSSL_i2d_PKCS7_bio");

    if (!bio || !p7) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    if ((len = wolfSSL_i2d_PKCS7(p7, &output)) ==
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE))
    {
        WOLFSSL_MSG("wolfSSL_i2d_PKCS7 error");
        goto cleanup;
    }

    if (wolfSSL_BIO_write(bio, output, len) <= 0) {
        WOLFSSL_MSG("wolfSSL_BIO_write error");
        goto cleanup;
    }

    ret = WOLFSSL_SUCCESS;
cleanup:
    XFREE(output, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/**
 * Creates and returns a PKCS7 signedData structure.
 *
 * Inner content type is set to DATA to match OpenSSL behavior.
 *
 * signer   - certificate to sign bundle with
 * pkey     - private key matching signer
 * certs    - optional additional set of certificates to include
 * in       - input data to be signed
 * flags    - optional set of flags to control sign behavior
 *
 *    PKCS7_BINARY   - Do not translate input data to MIME canonical
 *                     format (\r\n line endings), thus preventing corruption of
 *                     binary content.
 *    PKCS7_TEXT     - Prepend MIME headers for text/plain to content.
 *    PKCS7_DETACHED - Set signature detached, omit content from output bundle.
 *    PKCS7_STREAM   - initialize PKCS7 struct for signing, do not read data.
 *
 * Flags not currently supported:
 *    PKCS7_NOCERTS  - Do not include the signer cert in the output bundle.
 *    PKCS7_PARTIAL  - Allow for PKCS7_sign() to be only partially set up,
 *                     then signers etc to be added separately before
 *                     calling PKCS7_final().
 *
 * Returns valid PKCS7 structure pointer, or NULL if an error occurred.
 */
PKCS7* wolfSSL_PKCS7_sign(WOLFSSL_X509* signer, WOLFSSL_EVP_PKEY* pkey,
        WOLFSSL_STACK* certs, WOLFSSL_BIO* in, int flags)
{
    int err = 0;
    WOLFSSL_PKCS7* p7 = NULL;
    WOLFSSL_STACK* cert = certs;

    WOLFSSL_ENTER("wolfSSL_PKCS7_sign");

    if (flags & PKCS7_NOCERTS) {
        WOLFSSL_MSG("PKCS7_NOCERTS flag not yet supported");
        err = 1;
    }

    if (flags & PKCS7_PARTIAL) {
        WOLFSSL_MSG("PKCS7_PARTIAL flag not yet supported");
        err = 1;
    }

    if ((err == 0) && (signer == NULL || signer->derCert == NULL ||
                       signer->derCert->length == 0)) {
        WOLFSSL_MSG("Bad function arg, signer is NULL or incomplete");
        err = 1;
    }

    if ((err == 0) && (pkey == NULL || pkey->pkey.ptr == NULL ||
                       pkey->pkey_sz <= 0)) {
        WOLFSSL_MSG("Bad function arg, pkey is NULL or incomplete");
        err = 1;
    }

    if ((err == 0) && (in == NULL) && !(flags & PKCS7_STREAM)) {
        WOLFSSL_MSG("input data required unless PKCS7_STREAM used");
        err = 1;
    }

    if ((err == 0) && ((p7 = (WOLFSSL_PKCS7*)wolfSSL_PKCS7_new()) == NULL)) {
        WOLFSSL_MSG("Error allocating new WOLFSSL_PKCS7");
        err = 1;
    }

    /* load signer certificate */
    if (err == 0) {
        if (wc_PKCS7_InitWithCert(&p7->pkcs7, signer->derCert->buffer,
                                  signer->derCert->length) != 0) {
            WOLFSSL_MSG("Failed to load signer certificate");
            err = 1;
        }
    }

    /* set signer private key, data types, defaults */
    if (err == 0) {
        p7->pkcs7.privateKey = (byte*)pkey->pkey.ptr;
        p7->pkcs7.privateKeySz = (word32)pkey->pkey_sz;
        p7->pkcs7.contentOID = DATA;  /* inner content default is DATA */
        p7->pkcs7.hashOID = SHA256h;  /* default to SHA-256 hash type */
        p7->type = SIGNED_DATA;       /* PKCS7_final switches on type */
    }

    /* add additional chain certs if provided */
    while (cert && (err == 0)) {
        if (cert->data.x509 != NULL && cert->data.x509->derCert != NULL) {
            if (wc_PKCS7_AddCertificate(&p7->pkcs7,
                                cert->data.x509->derCert->buffer,
                                cert->data.x509->derCert->length) != 0) {
                WOLFSSL_MSG("Error in wc_PKCS7_AddCertificate");
                err = 1;
            }
        }
        cert = cert->next;
    }

    if ((err == 0) && (flags & PKCS7_DETACHED)) {
        if (wc_PKCS7_SetDetached(&p7->pkcs7, 1) != 0) {
            WOLFSSL_MSG("Failed to set signature detached");
            err = 1;
        }
    }

    if ((err == 0) && (flags & PKCS7_STREAM)) {
        /* if streaming, return before finalizing */
        return (PKCS7*)p7;
    }

    if ((err == 0) && (wolfSSL_PKCS7_final((PKCS7*)p7, in, flags) != 1)) {
        WOLFSSL_MSG("Error calling wolfSSL_PKCS7_final");
        err = 1;
    }

    if ((err != 0) && (p7 != NULL)) {
        wolfSSL_PKCS7_free((PKCS7*)p7);
        p7 = NULL;
    }

    return (PKCS7*)p7;
}

#ifdef HAVE_SMIME

#ifndef MAX_MIME_LINE_LEN
    #define MAX_MIME_LINE_LEN 1024
#endif

/**
 * Copy input BIO to output BIO, but convert all line endings to CRLF (\r\n),
 * used by PKCS7_final().
 *
 * in  - input WOLFSSL_BIO to be converted
 * out - output WOLFSSL_BIO to hold copy of in, with line endings adjusted
 *
 * Return 0 on success, negative on error
 */
static int wolfSSL_BIO_to_MIME_crlf(WOLFSSL_BIO* in, WOLFSSL_BIO* out)
{
    int ret = 0;
    int lineLen = 0;
    word32 canonLineLen = 0;
    char* canonLine = NULL;
#ifdef WOLFSSL_SMALL_STACK
    char* line = NULL;
#else
    char line[MAX_MIME_LINE_LEN];
#endif

    if (in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    line = (char*)XMALLOC(MAX_MIME_LINE_LEN, in->heap,
                          DYNAMIC_TYPE_TMP_BUFFER);
    if (line == NULL) {
        return MEMORY_E;
    }
#endif
    XMEMSET(line, 0, MAX_MIME_LINE_LEN);

    while ((lineLen = wolfSSL_BIO_gets(in, line, MAX_MIME_LINE_LEN)) > 0) {

        if (line[lineLen - 1] == '\r' || line[lineLen - 1] == '\n') {
            canonLineLen = (word32)lineLen;
            if ((canonLine = wc_MIME_single_canonicalize(
                                line, &canonLineLen)) == NULL) {
                ret = WOLFSSL_FATAL_ERROR;
                break;
            }

            /* remove trailing null */
            if (canonLineLen >= 1 && canonLine[canonLineLen-1] == '\0') {
                canonLineLen--;
            }

            if (wolfSSL_BIO_write(out, canonLine, (int)canonLineLen) < 0) {
                ret = WOLFSSL_FATAL_ERROR;
                break;
            }
            XFREE(canonLine, NULL, DYNAMIC_TYPE_PKCS7);
            canonLine = NULL;
        }
        else {
            /* no line ending in current line, write direct to out */
            if (wolfSSL_BIO_write(out, line, lineLen) < 0) {
                ret = WOLFSSL_FATAL_ERROR;
                break;
            }
        }
    }

    XFREE(canonLine, NULL, DYNAMIC_TYPE_PKCS7);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(line, in->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#endif /* HAVE_SMIME */

/* Used by both PKCS7_final() and PKCS7_verify() */
static const char contTypeText[] = "Content-Type: text/plain\r\n\r\n";

/**
 * Finalize PKCS7 structure, currently supports signedData only.
 *
 * Does not generate final bundle (ie: signedData), but finalizes
 * the PKCS7 structure in preparation for a output function to be called next.
 *
 * pkcs7 - initialized PKCS7 structure, populated with signer, etc
 * in    - input data
 * flags - flags to control PKCS7 behavior. Other flags except those noted
 *         below are ignored:
 *
 *    PKCS7_BINARY - Do not translate input data to MIME canonical
 *                   format (\r\n line endings), thus preventing corruption of
 *                   binary content.
 *    PKCS7_TEXT   - Prepend MIME headers for text/plain to content.
 *
 * Returns 1 on success, 0 on error
 */
int wolfSSL_PKCS7_final(PKCS7* pkcs7, WOLFSSL_BIO* in, int flags)
{
    int ret = 1;
    int memSz = 0;
    unsigned char* mem = NULL;
    WOLFSSL_PKCS7* p7 = (WOLFSSL_PKCS7*)pkcs7;
    WOLFSSL_BIO* data = NULL;

    WOLFSSL_ENTER("wolfSSL_PKCS7_final");

    if (p7 == NULL || in == NULL) {
        WOLFSSL_MSG("Bad input args to PKCS7_final");
        ret = 0;
    }

    if (ret == 1) {
        if ((data = wolfSSL_BIO_new(wolfSSL_BIO_s_mem())) == NULL) {
            WOLFSSL_MSG("Error in wolfSSL_BIO_new");
            ret = 0;
        }
    }

    /* prepend Content-Type header if PKCS7_TEXT */
    if ((ret == 1) && (flags & PKCS7_TEXT)) {
        if (wolfSSL_BIO_write(data, contTypeText,
                              (int)XSTR_SIZEOF(contTypeText)) < 0) {
            WOLFSSL_MSG("Error prepending Content-Type header");
            ret = 0;
        }
    }

    /* convert line endings to CRLF if !PKCS7_BINARY */
    if (ret == 1) {
        if (flags & PKCS7_BINARY) {

            /* no CRLF conversion, direct copy content */
            if ((memSz = wolfSSL_BIO_get_len(in)) <= 0) {
                ret = 0;
            }
            if (ret == 1) {
                mem = (unsigned char*)XMALLOC(memSz, in->heap,
                                              DYNAMIC_TYPE_TMP_BUFFER);
                if (mem == NULL) {
                    WOLFSSL_MSG("Failed to allocate memory for input data");
                    ret = 0;
                }
            }

            if (ret == 1) {
                if (wolfSSL_BIO_read(in, mem, memSz) != memSz) {
                    WOLFSSL_MSG("Error reading from input BIO");
                    ret = 0;
                }
                else if (wolfSSL_BIO_write(data, mem, memSz) < 0) {
                    ret = 0;
                }
            }

            XFREE(mem, in->heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        else {
    #ifdef HAVE_SMIME
            /* convert content line endings to CRLF */
            if (wolfSSL_BIO_to_MIME_crlf(in, data) != 0) {
                WOLFSSL_MSG("Error converting line endings to CRLF");
                ret = 0;
            }
            else {
                p7->pkcs7.contentCRLF = 1;
            }
    #else
            WOLFSSL_MSG("Without PKCS7_BINARY requires wolfSSL to be built "
                        "with HAVE_SMIME");
            ret = 0;
    #endif
        }
    }

    if ((ret == 1) && ((memSz = wolfSSL_BIO_get_mem_data(data, &mem)) < 0)) {
        WOLFSSL_MSG("Error in wolfSSL_BIO_get_mem_data");
        ret = 0;
    }

    if (ret == 1) {
        XFREE(p7->data, NULL, DYNAMIC_TYPE_PKCS7);
        p7->data = (byte*)XMALLOC(memSz, NULL, DYNAMIC_TYPE_PKCS7);
        if (p7->data == NULL) {
            ret = 0;
        }
        else {
            XMEMCPY(p7->data, mem, memSz);
            p7->len = memSz;
        }
    }

    if (ret == 1) {
        p7->pkcs7.content = p7->data;
        p7->pkcs7.contentSz = (word32)p7->len;
    }

    if (data != NULL) {
        wolfSSL_BIO_free(data);
    }

    return ret;
}

int wolfSSL_PKCS7_verify(PKCS7* pkcs7, WOLFSSL_STACK* certs,
        WOLFSSL_X509_STORE* store, WOLFSSL_BIO* in, WOLFSSL_BIO* out, int flags)
{
    int i, ret = 0;
    unsigned char* mem = NULL;
    int memSz = 0;
    WOLFSSL_PKCS7* p7 = (WOLFSSL_PKCS7*)pkcs7;
    int contTypeLen;
    WOLFSSL_X509* signer = NULL;
    WOLFSSL_STACK* signers = NULL;

    WOLFSSL_ENTER("wolfSSL_PKCS7_verify");

    if (pkcs7 == NULL)
        return WOLFSSL_FAILURE;

    if (in != NULL) {
        if ((memSz = wolfSSL_BIO_get_mem_data(in, &mem)) < 0)
            return WOLFSSL_FAILURE;

        p7->pkcs7.content = mem;
        p7->pkcs7.contentSz = (word32)memSz;
    }

    /* certs is the list of certificates to find the cert with issuer/serial. */
    (void)certs;
    /* store is the certificate store to use to verify signer certificate
     * associated with the signers.
     */
    (void)store;

    ret = wc_PKCS7_VerifySignedData(&p7->pkcs7, p7->data, p7->len);
    if (ret != 0)
        return WOLFSSL_FAILURE;

    if ((flags & PKCS7_NOVERIFY) != PKCS7_NOVERIFY) {
        /* Verify signer certificates */
        if (store == NULL || store->cm == NULL) {
            WOLFSSL_MSG("No store or store certs, but PKCS7_NOVERIFY not set");
            return WOLFSSL_FAILURE;
        }

        signers = wolfSSL_PKCS7_get0_signers(pkcs7, certs, flags);
        if (signers == NULL) {
            WOLFSSL_MSG("No signers found to verify");
            return WOLFSSL_FAILURE;
        }
        for (i = 0; i < wolfSSL_sk_X509_num(signers); i++) {
            signer = wolfSSL_sk_X509_value(signers, i);

            if (wolfSSL_CertManagerVerifyBuffer(store->cm,
                        signer->derCert->buffer,
                        signer->derCert->length,
                        WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
                WOLFSSL_MSG("Failed to verify signer certificate");
                wolfSSL_sk_X509_pop_free(signers, NULL);
                return WOLFSSL_FAILURE;
            }
        }
        wolfSSL_sk_X509_pop_free(signers, NULL);
    }

    if (flags & PKCS7_TEXT) {
        /* strip MIME header for text/plain, otherwise error */
        contTypeLen = XSTR_SIZEOF(contTypeText);
        if ((p7->pkcs7.contentSz < (word32)contTypeLen) ||
            (XMEMCMP(p7->pkcs7.content, contTypeText, contTypeLen) != 0)) {
            WOLFSSL_MSG("Error PKCS7 Content-Type not found with PKCS7_TEXT");
            return WOLFSSL_FAILURE;
        }
        p7->pkcs7.content += contTypeLen;
        p7->pkcs7.contentSz -= contTypeLen;
    }

    if (out != NULL) {
        wolfSSL_BIO_write(out, p7->pkcs7.content, p7->pkcs7.contentSz);
    }

    WOLFSSL_LEAVE("wolfSSL_PKCS7_verify", WOLFSSL_SUCCESS);

    return WOLFSSL_SUCCESS;
}

/**
 * This API was added as a helper function for libest. It
 * encodes a stack of certificates to pkcs7 format.
 * @param pkcs7 PKCS7 parameter object
 * @param certs WOLFSSL_STACK_OF(WOLFSSL_X509)*
 * @param out   Output bio
 * @return WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on failure
 */
int wolfSSL_PKCS7_encode_certs(PKCS7* pkcs7, WOLFSSL_STACK* certs,
        WOLFSSL_BIO* out)
{
    int ret;
    WOLFSSL_PKCS7* p7;
    WOLFSSL_ENTER("wolfSSL_PKCS7_encode_certs");

    if (!pkcs7 || !certs || !out) {
        WOLFSSL_MSG("Bad parameter");
        return WOLFSSL_FAILURE;
    }

    p7 = (WOLFSSL_PKCS7*)pkcs7;

    /* take ownership of certs */
    p7->certs = certs;
    /* TODO: takes ownership even on failure below but not on above failure. */

    if (pkcs7->certList) {
        WOLFSSL_MSG("wolfSSL_PKCS7_encode_certs called multiple times on same "
                    "struct");
        return WOLFSSL_FAILURE;
    }

    if (certs) {
        /* Save some of the values */
        int hashOID = pkcs7->hashOID;
        byte version = pkcs7->version;

        if (!certs->data.x509 || !certs->data.x509->derCert) {
            WOLFSSL_MSG("Missing cert");
            return WOLFSSL_FAILURE;
        }

        if (wc_PKCS7_InitWithCert(pkcs7, certs->data.x509->derCert->buffer,
                                      certs->data.x509->derCert->length) != 0) {
            WOLFSSL_MSG("wc_PKCS7_InitWithCert error");
            return WOLFSSL_FAILURE;
        }
        certs = certs->next;

        pkcs7->hashOID = hashOID;
        pkcs7->version = version;
    }

    /* Add the certs to the PKCS7 struct */
    while (certs) {
        if (!certs->data.x509 || !certs->data.x509->derCert) {
            WOLFSSL_MSG("Missing cert");
            return WOLFSSL_FAILURE;
        }
        if (wc_PKCS7_AddCertificate(pkcs7, certs->data.x509->derCert->buffer,
                                      certs->data.x509->derCert->length) != 0) {
            WOLFSSL_MSG("wc_PKCS7_AddCertificate error");
            return WOLFSSL_FAILURE;
        }
        certs = certs->next;
    }

    if (wc_PKCS7_SetSignerIdentifierType(pkcs7, DEGENERATE_SID) != 0) {
        WOLFSSL_MSG("wc_PKCS7_SetSignerIdentifierType error");
        return WOLFSSL_FAILURE;
    }

    ret = wolfSSL_i2d_PKCS7_bio(out, pkcs7);

    return ret;
}

/******************************************************************************
* wolfSSL_PEM_write_bio_PKCS7 - writes the PKCS7 data to BIO
*
* RETURNS:
* returns WOLFSSL_SUCCESS on success, otherwise returns WOLFSSL_FAILURE
*/
int wolfSSL_PEM_write_bio_PKCS7(WOLFSSL_BIO* bio, PKCS7* p7)
{
#ifdef WOLFSSL_SMALL_STACK
    byte* outputHead;
    byte* outputFoot;
#else
    byte outputHead[2048];
    byte outputFoot[2048];
#endif
    word32 outputHeadSz = 2048;
    word32 outputFootSz = 2048;
    word32 outputSz = 0;
    byte*  output = NULL;
    byte*  pem = NULL;
    int    pemSz = -1;
    enum wc_HashType hashType;
    byte hashBuf[WC_MAX_DIGEST_SIZE];
    word32 hashSz = -1;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_PKCS7");

    if (bio == NULL || p7 == NULL)
        return WOLFSSL_FAILURE;

#ifdef WOLFSSL_SMALL_STACK
    outputHead = (byte*)XMALLOC(outputHeadSz, bio->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (outputHead == NULL)
        return MEMORY_E;

    outputFoot = (byte*)XMALLOC(outputFootSz, bio->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (outputFoot == NULL)
        goto error;

#endif

    XMEMSET(hashBuf, 0, WC_MAX_DIGEST_SIZE);
    XMEMSET(outputHead, 0, outputHeadSz);
    XMEMSET(outputFoot, 0, outputFootSz);

    hashType = wc_OidGetHash(p7->hashOID);
    hashSz = (word32)wc_HashGetDigestSize(hashType);
    if (hashSz > WC_MAX_DIGEST_SIZE)
        goto error;

    /* only SIGNED_DATA is supported */
    switch (p7->contentOID) {
        case SIGNED_DATA:
            break;
        default:
            WOLFSSL_MSG("Unknown PKCS#7 Type");
            goto error;
    };

    if ((wc_PKCS7_EncodeSignedData_ex(p7, hashBuf, hashSz,
        outputHead, &outputHeadSz, outputFoot, &outputFootSz)) != 0)
        goto error;

    outputSz = outputHeadSz + p7->contentSz + outputFootSz;
    output = (byte*)XMALLOC(outputSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (!output)
        goto error;

    XMEMSET(output, 0, outputSz);
    outputSz = 0;
    XMEMCPY(&output[outputSz], outputHead, outputHeadSz);
    outputSz += outputHeadSz;
    XMEMCPY(&output[outputSz], p7->content, p7->contentSz);
    outputSz += p7->contentSz;
    XMEMCPY(&output[outputSz], outputFoot, outputFootSz);
    outputSz += outputFootSz;

    /* get PEM size */
    pemSz = wc_DerToPemEx(output, outputSz, NULL, 0, NULL, CERT_TYPE);
    if (pemSz < 0)
        goto error;

    pemSz++; /* for '\0'*/

    /* create PEM buffer and convert from DER to PEM*/
    if ((pem = (byte*)XMALLOC(pemSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER))
                                                                        == NULL)
        goto error;

    XMEMSET(pem, 0, pemSz);

    if (wc_DerToPemEx(output, outputSz, pem, (word32)pemSz, NULL, CERT_TYPE) < 0) {
        goto error;
    }
    if ((wolfSSL_BIO_write(bio, pem, pemSz) == pemSz)) {
        XFREE(output, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(pem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(outputHead, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(outputFoot, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return WOLFSSL_SUCCESS;
    }

error:
#ifdef WOLFSSL_SMALL_STACK
    XFREE(outputHead, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(outputFoot, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    XFREE(output, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return WOLFSSL_FAILURE;
}

#ifdef HAVE_SMIME
/*****************************************************************************
* wolfSSL_SMIME_read_PKCS7 - Reads the given S/MIME message and parses it into
* a PKCS7 object. In case of a multipart message, stores the signed data in
* bcont.
*
* RETURNS:
* returns pointer to a PKCS7 structure on success, otherwise returns NULL
*/
PKCS7* wolfSSL_SMIME_read_PKCS7(WOLFSSL_BIO* in,
        WOLFSSL_BIO** bcont)
{
    MimeHdr* allHdrs = NULL;
    MimeHdr* curHdr = NULL;
    MimeParam* curParam = NULL;
    int inLen = 0;
    byte* bcontMem = NULL;
    int bcontMemSz = 0;
    int sectionLen = 0;
    int ret = -1;
    char* section = NULL;
    char* canonLine = NULL;
    char* canonSection = NULL;
    PKCS7* pkcs7 = NULL;
    word32 outLen = 0;
    word32 canonLineLen = 0;
    byte* out = NULL;
    byte* outHead = NULL;

    int canonPos = 0;
    int lineLen = 0;
    int remainLen = 0;
    byte isEnd = 0;
    size_t canonSize = 0;
    size_t boundLen = 0;
    char* boundary = NULL;

    static const char kContType[] = "Content-Type";
    static const char kCTE[] = "Content-Transfer-Encoding";
    static const char kMultSigned[] = "multipart/signed";
    static const char kAppPkcsSign[] = "application/pkcs7-signature";
    static const char kAppXPkcsSign[] = "application/x-pkcs7-signature";
    static const char kAppPkcs7Mime[] = "application/pkcs7-mime";
    static const char kAppXPkcs7Mime[] = "application/x-pkcs7-mime";

    WOLFSSL_ENTER("wolfSSL_SMIME_read_PKCS7");

    if (in == NULL || bcont == NULL) {
        goto error;
    }
    inLen = wolfSSL_BIO_get_len(in);
    if (inLen <= 0) {
        goto error;
    }
    remainLen = wolfSSL_BIO_get_len(in);
    if (remainLen <= 0) {
        goto error;
    }

    section = (char*)XMALLOC(remainLen+1, NULL, DYNAMIC_TYPE_PKCS7);
    if (section == NULL) {
        goto error;
    }
    lineLen = wolfSSL_BIO_gets(in, section, remainLen);
    if (lineLen <= 0) {
        goto error;
    }
    while (isEnd == 0 && remainLen > 0) {
        sectionLen += lineLen;
        remainLen -= lineLen;
        lineLen = wolfSSL_BIO_gets(in, &section[sectionLen], remainLen);
        if (lineLen <= 0) {
            goto error;
        }
        /* Line with just newline signals end of headers. */
        if ((lineLen==2 && !XSTRNCMP(&section[sectionLen],
                                     "\r\n", 2)) ||
            (lineLen==1 && (section[sectionLen] == '\r' ||
                            section[sectionLen] == '\n'))) {
            isEnd = 1;
        }
    }
    section[sectionLen] = '\0';
    ret = wc_MIME_parse_headers(section, sectionLen, &allHdrs);
    if (ret < 0) {
        WOLFSSL_MSG("Parsing MIME headers failed.");
        goto error;
    }
    isEnd = 0;
    section[0] = '\0';
    sectionLen = 0;

    curHdr = wc_MIME_find_header_name(kContType, allHdrs);
    if (curHdr && !XSTRNCMP(curHdr->body, kMultSigned,
                            XSTR_SIZEOF(kMultSigned))) {
        curParam = wc_MIME_find_param_attr("protocol", curHdr->params);
        if (curParam && (!XSTRNCMP(curParam->value, kAppPkcsSign,
                                   XSTR_SIZEOF(kAppPkcsSign)) ||
                         !XSTRNCMP(curParam->value, kAppXPkcsSign,
                                   XSTR_SIZEOF(kAppXPkcsSign)))) {
            curParam = wc_MIME_find_param_attr("boundary", curHdr->params);
            if (curParam == NULL) {
                goto error;
            }

            boundLen = XSTRLEN(curParam->value) + 2;
            boundary = (char*)XMALLOC(boundLen+1, NULL, DYNAMIC_TYPE_PKCS7);
            if (boundary == NULL) {
                goto error;
            }
            XMEMSET(boundary, 0, (word32)(boundLen+1));
            boundary[0] = boundary[1] = '-';
            /* analyzers have issues with using strncpy and strcpy here */
            XMEMCPY(&boundary[2], curParam->value, boundLen - 2);

            /* Parse up to first boundary, ignore everything here. */
            lineLen = wolfSSL_BIO_gets(in, section, remainLen);
            if (lineLen <= 0) {
                goto error;
            }
            while (XSTRNCMP(&section[sectionLen], boundary, boundLen) &&
                   remainLen > 0) {
                sectionLen += lineLen;
                remainLen -= lineLen;
                lineLen = wolfSSL_BIO_gets(in, &section[sectionLen],
                                           remainLen);
                if (lineLen <= 0) {
                    goto error;
                }
            }

            section[0] = '\0';
            sectionLen = 0;
            canonSize = (size_t)remainLen + 1;
            canonSection = (char*)XMALLOC(canonSize, NULL,
                                          DYNAMIC_TYPE_PKCS7);
            if (canonSection == NULL) {
                goto error;
            }

            lineLen = wolfSSL_BIO_gets(in, section, remainLen);
            if (lineLen < 0) {
                goto error;
            }
            while (XSTRNCMP(&section[sectionLen], boundary, boundLen) &&
                            remainLen > 0) {
                canonLineLen = (word32)lineLen;
                canonLine = wc_MIME_single_canonicalize(&section[sectionLen],
                                                        &canonLineLen);
                if (canonLine == NULL) {
                    goto error;
                }
                /* If line endings were added, the initial length may be
                 * exceeded. */
                if ((canonPos + canonLineLen) >= canonSize) {
                    canonSize = canonPos + canonLineLen;
                    canonSection = (char*)XREALLOC(canonSection, canonSize,
                                                   NULL, DYNAMIC_TYPE_PKCS7);
                    if (canonSection == NULL) {
                        goto error;
                    }
                }
                XMEMCPY(&canonSection[canonPos], canonLine,
                        (int)canonLineLen - 1);
                canonPos += canonLineLen - 1;
                XFREE(canonLine, NULL, DYNAMIC_TYPE_PKCS7);
                canonLine = NULL;

                sectionLen += lineLen;
                remainLen -= lineLen;

                lineLen = wolfSSL_BIO_gets(in, &section[sectionLen],
                                           remainLen);
                if (lineLen <= 0) {
                    goto error;
                }
            }

            if (canonPos > 0) {
                canonPos--;
            }

            /* Strip the final trailing newline.  Support \r, \n or \r\n. */
            if (canonSection[canonPos] == '\n') {
                if (canonPos > 0) {
                    canonPos--;
                }
            }

            if (canonSection[canonPos] == '\r') {
                if (canonPos > 0) {
                    canonPos--;
                }
            }

            canonSection[canonPos+1] = '\0';

            *bcont = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
            ret = wolfSSL_BIO_write(*bcont, canonSection,
                                    canonPos + 1);
            if (ret != (canonPos+1)) {
                goto error;
            }
            if ((bcontMemSz = wolfSSL_BIO_get_mem_data(*bcont, &bcontMem))
                                                                          < 0) {
                goto error;
            }
            XFREE(canonSection, NULL, DYNAMIC_TYPE_PKCS7);
            canonSection = NULL;

            wc_MIME_free_hdrs(allHdrs);
            allHdrs = NULL;
            section[0] = '\0';
            sectionLen = 0;
            lineLen = wolfSSL_BIO_gets(in, section, remainLen);
            if (lineLen <= 0) {
                goto error;
            }
            while (isEnd == 0 && remainLen > 0) {
                sectionLen += lineLen;
                remainLen -= lineLen;
                lineLen = wolfSSL_BIO_gets(in, &section[sectionLen],
                                           remainLen);
                if (lineLen <= 0) {
                    goto error;
                }
                /* Line with just newline signals end of headers. */
                if ((lineLen==2 && !XSTRNCMP(&section[sectionLen],
                                             "\r\n", 2)) ||
                    (lineLen==1 && (section[sectionLen] == '\r' ||
                                    section[sectionLen] == '\n'))) {
                    isEnd = 1;
                }
            }
            section[sectionLen] = '\0';
            ret = wc_MIME_parse_headers(section, sectionLen, &allHdrs);
            if (ret < 0) {
                WOLFSSL_MSG("Parsing MIME headers failed.");
                goto error;
            }
            curHdr = wc_MIME_find_header_name(kContType, allHdrs);
            if (curHdr == NULL || (XSTRNCMP(curHdr->body, kAppPkcsSign,
                                   XSTR_SIZEOF(kAppPkcsSign)) &&
                                   XSTRNCMP(curHdr->body, kAppXPkcsSign,
                                   XSTR_SIZEOF(kAppXPkcsSign)))) {
                WOLFSSL_MSG("S/MIME headers not found inside "
                            "multipart message.\n");
                goto error;
            }

            section[0] = '\0';
            sectionLen = 0;
            lineLen = wolfSSL_BIO_gets(in, section, remainLen);
            while (XSTRNCMP(&section[sectionLen], boundary, boundLen) &&
                   remainLen > 0) {
                sectionLen += lineLen;
                remainLen -= lineLen;
                lineLen = wolfSSL_BIO_gets(in, &section[sectionLen],
                                           remainLen);
                if (lineLen <= 0) {
                    goto error;
                }
            }

            XFREE(boundary, NULL, DYNAMIC_TYPE_PKCS7);
            boundary = NULL;
        }
    }
    else if (curHdr && (!XSTRNCMP(curHdr->body, kAppPkcs7Mime,
                                  XSTR_SIZEOF(kAppPkcs7Mime)) ||
                        !XSTRNCMP(curHdr->body, kAppXPkcs7Mime,
                                  XSTR_SIZEOF(kAppXPkcs7Mime)))) {
        sectionLen = wolfSSL_BIO_get_len(in);
        if (sectionLen <= 0) {
            goto error;
        }
        ret = wolfSSL_BIO_read(in, section, sectionLen);
        if (ret < 0 || ret != sectionLen) {
            WOLFSSL_MSG("Error reading input BIO.");
            goto error;
        }
    }
    else {
        WOLFSSL_MSG("S/MIME headers not found.");
        goto error;
    }

    curHdr = wc_MIME_find_header_name(kCTE, allHdrs);
    if (curHdr == NULL) {
        WOLFSSL_MSG("Content-Transfer-Encoding header not found, "
                    "assuming base64 encoding.");
    }
    else if (XSTRNCMP(curHdr->body, "base64", XSTRLEN("base64"))) {
        WOLFSSL_MSG("S/MIME encodings other than base64 are not "
                    "currently supported.\n");
        goto error;
    }

    if (section == NULL || sectionLen <= 0) {
        goto error;
    }
    outLen = (word32)((sectionLen*3+3)/4)+1;
    out = (byte*)XMALLOC(outLen*sizeof(byte), NULL, DYNAMIC_TYPE_PKCS7);
    outHead = out;
    if (outHead == NULL) {
        goto error;
    }
    /* Strip trailing newlines. */
    while ((sectionLen > 0) &&
           (section[sectionLen-1] == '\r' || section[sectionLen-1] == '\n')) {
        sectionLen--;
    }
    section[sectionLen] = '\0';
    ret = Base64_Decode((const byte*)section, (word32)sectionLen, out, &outLen);
    if (ret < 0) {
        WOLFSSL_MSG("Error base64 decoding S/MIME message.");
        goto error;
    }
    pkcs7 = wolfSSL_d2i_PKCS7_only(NULL, (const unsigned char**)&out, (int)outLen,
        bcontMem, (word32)bcontMemSz);

    wc_MIME_free_hdrs(allHdrs);
    XFREE(outHead, NULL, DYNAMIC_TYPE_PKCS7);
    XFREE(section, NULL, DYNAMIC_TYPE_PKCS7);

    return pkcs7;

error:
    wc_MIME_free_hdrs(allHdrs);
    XFREE(boundary, NULL, DYNAMIC_TYPE_PKCS7);
    XFREE(outHead, NULL, DYNAMIC_TYPE_PKCS7);
    XFREE(section, NULL, DYNAMIC_TYPE_PKCS7);
    XFREE(canonSection, NULL, DYNAMIC_TYPE_PKCS7);
    XFREE(canonLine, NULL, DYNAMIC_TYPE_PKCS7);
    if (bcont) {
        wolfSSL_BIO_free(*bcont);
        *bcont = NULL; /* reset 'bcount' pointer to NULL on failure */
    }

    return NULL;
}

/* Convert hash algo OID (from Hash_Sum in asn.h) to SMIME string equivalent.
 * Returns hash algorithm string or "unknown" if not found */
static const char* wolfSSL_SMIME_HashOIDToString(int hashOID)
{
    switch (hashOID) {
        case MD5h:
            return "md5";
        case SHAh:
            return "sha1";
        case SHA224h:
            return "sha-224";
        case SHA256h:
            return "sha-256";
        case SHA384h:
            return "sha-384";
        case SHA512h:
            return "sha-512";
        case SHA3_224h:
            return "sha3-224";
        case SHA3_384h:
            return "sha3-384";
        case SHA3_512h:
            return "sha3-512";
        default:
            break;
    }

    return "unknown";
}

/* Convert PKCS#7 type (from PKCS7_TYPES in pkcs7.h) to SMIME string.
 * RFC2633 only defines signed-data, enveloped-data, certs-only.
 * Returns string on success, NULL on unknown type. */
static const char* wolfSSL_SMIME_PKCS7TypeToString(int type)
{
    switch (type) {
        case SIGNED_DATA:
            return "signed-data";
        case ENVELOPED_DATA:
            return "enveloped-data";
        default:
            break;
    }

    return NULL;
}

/**
 * Convert PKCS7 structure to SMIME format, adding necessary headers.
 *
 * Handles generation of PKCS7 bundle (ie: signedData). PKCS7 structure
 * should be set up beforehand with PKCS7_sign/final/etc. Output is always
 * Base64 encoded.
 *
 * out   - output BIO for SMIME formatted data to be placed
 * pkcs7 - input PKCS7 structure, initialized and set up
 * in    - input content to be encoded into PKCS7
 * flags - flags to control behavior of PKCS7 generation
 *
 * Returns 1 on success, 0 or negative on failure
 */
int wolfSSL_SMIME_write_PKCS7(WOLFSSL_BIO* out, PKCS7* pkcs7, WOLFSSL_BIO* in,
                              int flags)
{
    int i;
    int ret = 1;
    WOLFSSL_PKCS7* p7 = (WOLFSSL_PKCS7*)pkcs7;
    byte* p7out = NULL;
    int len = 0;

    char boundary[33]; /* 32 chars + \0 */
    byte* sigBase64 = NULL;
    word32 sigBase64Len = 0;
    const char* p7TypeString = NULL;

    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    if (out == NULL || p7 == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return 0;
    }

    if (in != NULL && (p7->pkcs7.content == NULL || p7->pkcs7.contentSz == 0 ||
                       p7->pkcs7.contentCRLF == 0)) {
        /* store and adjust content line endings for CRLF if needed */
        if (wolfSSL_PKCS7_final((PKCS7*)p7, in, flags) != 1) {
            ret = 0;
        }
    }

    if (ret > 0) {
        /* Generate signedData bundle, DER in output (dynamic) */
        if ((len = wolfSSL_i2d_PKCS7((PKCS7*)p7, &p7out)) ==
            WC_NO_ERR_TRACE(WOLFSSL_FAILURE))
        {
            WOLFSSL_MSG("Error in wolfSSL_i2d_PKCS7");
            ret = 0;
        }
    }

    /* Base64 encode signedData bundle */
    if (ret > 0) {
        if (Base64_Encode(p7out, (word32)len, NULL, &sigBase64Len) !=
            WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
            ret = 0;
        }
        else {
            sigBase64 = (byte*)XMALLOC(sigBase64Len, NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
            if (sigBase64 == NULL) {
                ret = 0;
            }
        }
    }

    if (ret > 0) {
        XMEMSET(sigBase64, 0, sigBase64Len);
        if (Base64_Encode(p7out, (word32)len, sigBase64, &sigBase64Len) < 0) {
            WOLFSSL_MSG("Error in Base64_Encode of signature");
            ret = 0;
        }
    }

    /* build up SMIME message */
    if (ret > 0) {
        if (flags & PKCS7_DETACHED) {

            /* generate random boundary */
            if (initGlobalRNG == 0 && wolfSSL_RAND_Init() != WOLFSSL_SUCCESS) {
                WOLFSSL_MSG("No RNG to use");
                ret = 0;
            }

            /* no need to generate random byte for null terminator (size-1) */
            if ((ret > 0) && (wc_RNG_GenerateBlock(&globalRNG, (byte*)boundary,
                                  sizeof(boundary) - 1 ) != 0)) {
                    WOLFSSL_MSG("Error in wc_RNG_GenerateBlock");
                    ret = 0;
            }

            if (ret > 0) {
                for (i = 0; i < (int)sizeof(boundary) - 1; i++) {
                    boundary[i] =
                        alphanum[boundary[i] % XSTR_SIZEOF(alphanum)];
                }
                boundary[sizeof(boundary)-1] = 0;
            }

            if (ret > 0) {
                /* S/MIME header beginning */
                ret = wolfSSL_BIO_printf(out,
                        "MIME-Version: 1.0\n"
                        "Content-Type: multipart/signed; "
                        "protocol=\"application/x-pkcs7-signature\"; "
                        "micalg=\"%s\"; "
                        "boundary=\"----%s\"\n\n"
                        "This is an S/MIME signed message\n\n"
                        "------%s\n",
                        wolfSSL_SMIME_HashOIDToString(p7->pkcs7.hashOID),
                        boundary, boundary);
            }

            if (ret > 0) {
                /* S/MIME content */
                ret = wolfSSL_BIO_write(out,
                        p7->pkcs7.content, p7->pkcs7.contentSz);
            }

            if (ret > 0) {
                /* S/SMIME header end boundary */
                ret = wolfSSL_BIO_printf(out,
                        "\n------%s\n", boundary);
            }

            if (ret > 0) {
                /* Signature and header */
                ret = wolfSSL_BIO_printf(out,
                        "Content-Type: application/x-pkcs7-signature; "
                        "name=\"smime.p7s\"\n"
                        "Content-Transfer-Encoding: base64\n"
                        "Content-Disposition: attachment; "
                        "filename=\"smime.p7s\"\n\n"
                        "%.*s\n" /* Base64 encoded signature */
                        "------%s--\n\n",
                        sigBase64Len, sigBase64,
                        boundary);
            }
        }
        else {
            p7TypeString = wolfSSL_SMIME_PKCS7TypeToString(p7->type);
            if (p7TypeString == NULL) {
                WOLFSSL_MSG("Unsupported PKCS7 SMIME type");
                ret = 0;
            }

            if (ret > 0) {
                /* not detached */
                ret = wolfSSL_BIO_printf(out,
                        "MIME-Version: 1.0\n"
                        "Content-Disposition: attachment; "
                        "filename=\"smime.p7m\"\n"
                        "Content-Type: application/x-pkcs7-mime; "
                        "smime-type=%s; name=\"smime.p7m\"\n"
                        "Content-Transfer-Encoding: base64\n\n"
                        "%.*s\n" /* signature */,
                        p7TypeString, sigBase64Len, sigBase64);
            }
        }
    }

    XFREE(p7out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sigBase64, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret > 0) {
        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}

#endif /* HAVE_SMIME */
#endif /* !NO_BIO */
#endif /* OPENSSL_ALL */

#endif /* HAVE_PKCS7 */
/*******************************************************************************
 * END OF PKCS7 APIs
 ******************************************************************************/

/*******************************************************************************
 * START OF PKCS12 APIs
 ******************************************************************************/
#ifdef OPENSSL_EXTRA

/* no-op function. Was initially used for adding encryption algorithms available
 * for PKCS12 */
void wolfSSL_PKCS12_PBE_add(void)
{
    WOLFSSL_ENTER("wolfSSL_PKCS12_PBE_add");
}

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
WOLFSSL_X509_PKCS12 *wolfSSL_d2i_PKCS12_fp(XFILE fp,
        WOLFSSL_X509_PKCS12 **pkcs12)
{
    WOLFSSL_ENTER("wolfSSL_d2i_PKCS12_fp");
    return (WOLFSSL_X509_PKCS12 *)wolfSSL_d2i_X509_fp_ex(fp, (void **)pkcs12,
        PKCS12_TYPE);
}
#endif /* !NO_FILESYSTEM */

#endif /* OPENSSL_EXTRA */

#if defined(HAVE_PKCS12)

#ifdef OPENSSL_EXTRA

#if !defined(NO_ASN) && !defined(NO_PWDBASED)

#ifndef NO_BIO
WC_PKCS12* wolfSSL_d2i_PKCS12_bio(WOLFSSL_BIO* bio, WC_PKCS12** pkcs12)
{
    WC_PKCS12* localPkcs12 = NULL;
    unsigned char* mem = NULL;
    long memSz;
    int ret = -1;

    WOLFSSL_ENTER("wolfSSL_d2i_PKCS12_bio");

    if (bio == NULL) {
        WOLFSSL_MSG("Bad Function Argument bio is NULL");
        return NULL;
    }

    memSz = wolfSSL_BIO_get_len(bio);
    if (memSz <= 0) {
        return NULL;
    }
    mem = (unsigned char*)XMALLOC(memSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        return NULL;
    }

    if (mem != NULL) {
        localPkcs12 = wc_PKCS12_new_ex(bio->heap);
        if (localPkcs12 == NULL) {
            WOLFSSL_MSG("Memory error");
        }
    }

    if (mem != NULL && localPkcs12 != NULL) {
        if (wolfSSL_BIO_read(bio, mem, (int)memSz) == memSz) {
            ret = wc_d2i_PKCS12(mem, (word32)memSz, localPkcs12);
            if (ret < 0) {
                WOLFSSL_MSG("Failed to get PKCS12 sequence");
            }
        }
        else {
            WOLFSSL_MSG("Failed to get data from bio struct");
        }
    }

    /* cleanup */
    XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret < 0 && localPkcs12 != NULL) {
        wc_PKCS12_free(localPkcs12);
        localPkcs12 = NULL;
    }
    if (pkcs12 != NULL)
        *pkcs12 = localPkcs12;

    return localPkcs12;
}

/* Converts the PKCS12 to DER format and outputs it into bio.
 *
 * bio is the structure to hold output DER
 * pkcs12 structure to create DER from
 *
 * return 1 for success or 0 if an error occurs
 */
int wolfSSL_i2d_PKCS12_bio(WOLFSSL_BIO *bio, WC_PKCS12 *pkcs12)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);

    WOLFSSL_ENTER("wolfSSL_i2d_PKCS12_bio");

    if ((bio != NULL) && (pkcs12 != NULL)) {
        word32 certSz = 0;
        byte *certDer = NULL;

        certSz = (word32)wc_i2d_PKCS12(pkcs12, &certDer, NULL);
        if ((certSz > 0) && (certDer != NULL)) {
            if (wolfSSL_BIO_write(bio, certDer, (int)certSz) == (int)certSz) {
                ret = WOLFSSL_SUCCESS;
            }
        }

        XFREE(certDer, NULL, DYNAMIC_TYPE_PKCS);
    }

    return ret;
}
#endif /* !NO_BIO */

/* Creates a new WC_PKCS12 structure
 *
 * pass  password to use
 * name  friendlyName to use
 * pkey  private key to go into PKCS12 bundle
 * cert  certificate to go into PKCS12 bundle
 * ca    extra certificates that can be added to bundle. Can be NULL
 * keyNID  type of encryption to use on the key (-1 means no encryption)
 * certNID type of encryption to use on the certificate
 * itt     number of iterations with encryption
 * macItt  number of iterations with mac creation
 * keyType flag for signature and/or encryption key
 *
 * returns a pointer to a new WC_PKCS12 structure on success and NULL on fail
 */
WC_PKCS12* wolfSSL_PKCS12_create(char* pass, char* name, WOLFSSL_EVP_PKEY* pkey,
        WOLFSSL_X509* cert, WOLF_STACK_OF(WOLFSSL_X509)* ca, int keyNID,
        int certNID, int itt, int macItt, int keyType)
{
    WC_PKCS12* pkcs12;
    WC_DerCertList* list = NULL;
    word32 passSz;
    byte* keyDer = NULL;
    word32 keyDerSz;
    byte* certDer;
    int certDerSz;

    WOLFSSL_ENTER("wolfSSL_PKCS12_create");

    if (pass == NULL || pkey == NULL || cert == NULL) {
        WOLFSSL_LEAVE("wolfSSL_PKCS12_create", BAD_FUNC_ARG);
        return NULL;
    }
    passSz = (word32)XSTRLEN(pass);

    keyDer = (byte*)pkey->pkey.ptr;
    keyDerSz = (word32)pkey->pkey_sz;

    certDer = (byte*)wolfSSL_X509_get_der(cert, &certDerSz);
    if (certDer == NULL) {
        return NULL;
    }

    if (ca != NULL) {
        unsigned long numCerts = ca->num;
        WOLFSSL_STACK* sk = ca;

        while (numCerts > 0 && sk != NULL) {
            byte* curDer;
            WC_DerCertList* cur;
            int   curDerSz = 0;

            cur = (WC_DerCertList*)XMALLOC(sizeof(WC_DerCertList), NULL,
                    DYNAMIC_TYPE_PKCS);
            if (cur == NULL) {
                wc_FreeCertList(list, NULL);
                return NULL;
            }

            curDer = (byte*)wolfSSL_X509_get_der(sk->data.x509, &curDerSz);
            if (curDer == NULL || curDerSz < 0) {
                XFREE(cur, NULL, DYNAMIC_TYPE_PKCS);
                wc_FreeCertList(list, NULL);
                return NULL;
            }

            cur->buffer = (byte*)XMALLOC(curDerSz, NULL, DYNAMIC_TYPE_PKCS);
            if (cur->buffer == NULL) {
                XFREE(cur, NULL, DYNAMIC_TYPE_PKCS);
                wc_FreeCertList(list, NULL);
                return NULL;
            }
            XMEMCPY(cur->buffer, curDer, curDerSz);
            cur->bufferSz = (word32)curDerSz;
            cur->next = list;
            list = cur;

            sk = sk->next;
            numCerts--;
        }
    }

    pkcs12 = wc_PKCS12_create(pass, passSz, name, keyDer, keyDerSz,
            certDer, (word32)certDerSz, list, keyNID, certNID, itt, macItt,
            keyType, NULL);

    if (ca != NULL) {
        wc_FreeCertList(list, NULL);
    }

    return pkcs12;
}


/* return WOLFSSL_SUCCESS on success, WOLFSSL_FAILURE on failure */
int wolfSSL_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
          WOLFSSL_EVP_PKEY** pkey, WOLFSSL_X509** cert,
          WOLF_STACK_OF(WOLFSSL_X509)** ca)
{
    void* heap = NULL;
    int ret;
    byte* certData = NULL;
    word32 certDataSz;
    byte* pk = NULL;
    word32 pkSz;
    WC_DerCertList* certList = NULL;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert *DeCert;
#else
    DecodedCert DeCert[1];
#endif

    WOLFSSL_ENTER("wolfSSL_PKCS12_parse");

    /* make sure we init return args */
    if (pkey) *pkey = NULL;
    if (cert) *cert = NULL;
    if (ca)   *ca = NULL;

    if (pkcs12 == NULL || psw == NULL || pkey == NULL || cert == NULL) {
        WOLFSSL_MSG("Bad argument value");
        return WOLFSSL_FAILURE;
    }

    heap  = wc_PKCS12_GetHeap(pkcs12);

    if (ca == NULL) {
        ret = wc_PKCS12_parse(pkcs12, psw, &pk, &pkSz, &certData, &certDataSz,
            NULL);
    }
    else {
        ret = wc_PKCS12_parse(pkcs12, psw, &pk, &pkSz, &certData, &certDataSz,
            &certList);
    }
    if (ret < 0) {
        WOLFSSL_LEAVE("wolfSSL_PKCS12_parse", ret);
        return WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_SMALL_STACK
    DeCert = (DecodedCert *)XMALLOC(sizeof(*DeCert), heap,
                                    DYNAMIC_TYPE_DCERT);
    if (DeCert == NULL) {
        WOLFSSL_MSG("out of memory");
        return WOLFSSL_FAILURE;
    }
#endif

    /* Decode cert and place in X509 stack struct */
    if (certList != NULL) {
        WC_DerCertList* current = certList;

        *ca = (WOLF_STACK_OF(WOLFSSL_X509)*)XMALLOC(
            sizeof(WOLF_STACK_OF(WOLFSSL_X509)), heap, DYNAMIC_TYPE_X509);
        if (*ca == NULL) {
            XFREE(pk, heap, DYNAMIC_TYPE_PUBLIC_KEY);
            XFREE(certData, heap, DYNAMIC_TYPE_PKCS);
            /* Free up WC_DerCertList and move on */
            while (current != NULL) {
                WC_DerCertList* next = current->next;

                XFREE(current->buffer, heap, DYNAMIC_TYPE_PKCS);
                XFREE(current, heap, DYNAMIC_TYPE_PKCS);
                current = next;
            }
            ret = WOLFSSL_FAILURE;
            goto out;
        }
        XMEMSET(*ca, 0, sizeof(WOLF_STACK_OF(WOLFSSL_X509)));

        /* add list of DER certs as X509's to stack */
        while (current != NULL) {
            WC_DerCertList*  toFree = current;
            WOLFSSL_X509* x509;

            x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), heap,
                DYNAMIC_TYPE_X509);
            InitX509(x509, 1, heap);
            InitDecodedCert(DeCert, current->buffer, current->bufferSz, heap);
            if (ParseCertRelative(DeCert, CERT_TYPE, NO_VERIFY, NULL, NULL) != 0) {
                WOLFSSL_MSG("Issue with parsing certificate");
                FreeDecodedCert(DeCert);
                wolfSSL_X509_free(x509);
            }
            else {
                if (CopyDecodedToX509(x509, DeCert) != 0) {
                    WOLFSSL_MSG("Failed to copy decoded cert");
                    FreeDecodedCert(DeCert);
                    wolfSSL_X509_free(x509);
                    wolfSSL_sk_X509_pop_free(*ca, NULL); *ca = NULL;
                    XFREE(pk, heap, DYNAMIC_TYPE_PUBLIC_KEY);
                    XFREE(certData, heap, DYNAMIC_TYPE_PKCS);
                    /* Free up WC_DerCertList */
                    while (current != NULL) {
                        WC_DerCertList* next = current->next;

                        XFREE(current->buffer, heap, DYNAMIC_TYPE_PKCS);
                        XFREE(current, heap, DYNAMIC_TYPE_PKCS);
                        current = next;
                    }
                    ret = WOLFSSL_FAILURE;
                    goto out;
                }
                FreeDecodedCert(DeCert);

                if (wolfSSL_sk_X509_push(*ca, x509) <= 0) {
                    WOLFSSL_MSG("Failed to push x509 onto stack");
                    wolfSSL_X509_free(x509);
                    wolfSSL_sk_X509_pop_free(*ca, NULL); *ca = NULL;
                    XFREE(pk, heap, DYNAMIC_TYPE_PUBLIC_KEY);
                    XFREE(certData, heap, DYNAMIC_TYPE_PKCS);

                    /* Free up WC_DerCertList */
                    while (current != NULL) {
                        WC_DerCertList* next = current->next;

                        XFREE(current->buffer, heap, DYNAMIC_TYPE_PKCS);
                        XFREE(current, heap, DYNAMIC_TYPE_PKCS);
                        current = next;
                    }
                    ret = WOLFSSL_FAILURE;
                    goto out;
                }
            }
            current = current->next;
            XFREE(toFree->buffer, heap, DYNAMIC_TYPE_PKCS);
            XFREE(toFree, heap, DYNAMIC_TYPE_PKCS);
        }
    }


    /* Decode cert and place in X509 struct */
    if (certData != NULL) {
        *cert = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), heap,
            DYNAMIC_TYPE_X509);
        if (*cert == NULL) {
            XFREE(pk, heap, DYNAMIC_TYPE_PUBLIC_KEY);
            if (ca != NULL) {
                wolfSSL_sk_X509_pop_free(*ca, NULL); *ca = NULL;
            }
            XFREE(certData, heap, DYNAMIC_TYPE_PKCS);
            ret = WOLFSSL_FAILURE;
            goto out;
        }
        InitX509(*cert, 1, heap);
        InitDecodedCert(DeCert, certData, certDataSz, heap);
        if (ParseCertRelative(DeCert, CERT_TYPE, NO_VERIFY, NULL, NULL) != 0) {
            WOLFSSL_MSG("Issue with parsing certificate");
        }
        if (CopyDecodedToX509(*cert, DeCert) != 0) {
            WOLFSSL_MSG("Failed to copy decoded cert");
            FreeDecodedCert(DeCert);
            XFREE(pk, heap, DYNAMIC_TYPE_PUBLIC_KEY);
            if (ca != NULL) {
                wolfSSL_sk_X509_pop_free(*ca, NULL); *ca = NULL;
            }
            wolfSSL_X509_free(*cert); *cert = NULL;
            XFREE(certData, heap, DYNAMIC_TYPE_PKCS);
            ret = WOLFSSL_FAILURE;
            goto out;
        }
        FreeDecodedCert(DeCert);
        XFREE(certData, heap, DYNAMIC_TYPE_PKCS);
    }


    /* get key type */
    ret = BAD_STATE_E;
    if (pk != NULL) { /* decode key if present */
        *pkey = wolfSSL_EVP_PKEY_new_ex(heap);
        if (*pkey == NULL) {
            wolfSSL_X509_free(*cert); *cert = NULL;
            if (ca != NULL) {
                wolfSSL_sk_X509_pop_free(*ca, NULL); *ca = NULL;
            }
            XFREE(pk, heap, DYNAMIC_TYPE_PUBLIC_KEY);
            ret = WOLFSSL_FAILURE;
            goto out;
        }

    #ifndef NO_RSA
        {
            const unsigned char* pt = pk;
            if (wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, pkey, &pt, pkSz) !=
                    NULL) {
                ret = 0;
            }
        }
    #endif /* NO_RSA */

    #ifdef HAVE_ECC
        if (ret != 0) { /* if is in fail state check if ECC key */
            const unsigned char* pt = pk;
            if (wolfSSL_d2i_PrivateKey(EVP_PKEY_EC, pkey, &pt, pkSz) !=
                    NULL) {
                ret = 0;
            }
        }
    #endif /* HAVE_ECC */
        XFREE(pk, heap, DYNAMIC_TYPE_PKCS);
        if (ret != 0) { /* if is in fail state and no PKEY then fail */
            wolfSSL_X509_free(*cert); *cert = NULL;
            if (ca != NULL) {
                wolfSSL_sk_X509_pop_free(*ca, NULL); *ca = NULL;
            }
            wolfSSL_EVP_PKEY_free(*pkey); *pkey = NULL;
            WOLFSSL_MSG("Bad PKCS12 key format");
            ret = WOLFSSL_FAILURE;
            goto out;
        }

        if (pkey != NULL && *pkey != NULL) {
            (*pkey)->save_type = 0;
        }
    }

    (void)ret;
    (void)ca;

    ret = WOLFSSL_SUCCESS;

out:

#ifdef WOLFSSL_SMALL_STACK
    XFREE(DeCert, heap, DYNAMIC_TYPE_DCERT);
#endif

    return ret;
}

int wolfSSL_PKCS12_verify_mac(WC_PKCS12 *pkcs12, const char *psw,
        int pswLen)
{
    WOLFSSL_ENTER("wolfSSL_PKCS12_verify_mac");

    if (!pkcs12) {
        return WOLFSSL_FAILURE;
    }

    return wc_PKCS12_verify_ex(pkcs12, (const byte*)psw, (word32)pswLen) == 0 ?
            WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}

#endif /* !NO_ASN && !NO_PWDBASED */

#endif /* OPENSSL_EXTRA */

#endif /* HAVE_PKCS12 */
/*******************************************************************************
 * END OF PKCS12 APIs
 ******************************************************************************/

#endif /* !WOLFCRYPT_ONLY && !NO_CERTS */

#endif /* !WOLFSSL_SSL_P7P12_INCLUDED */
