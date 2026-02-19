/* pk_rsa.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/internal.h>
#ifndef WC_NO_RNG
    #include <wolfssl/wolfcrypt/random.h>
#endif

#if !defined(WOLFSSL_PK_RSA_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning pk_rsa.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif

/*******************************************************************************
 * START OF RSA API
 ******************************************************************************/

#ifndef NO_RSA

/*
 * RSA METHOD
 * Could be used to hold function pointers to implementations of RSA operations.
 */

#if defined(OPENSSL_EXTRA)
/* Return a blank RSA method and set the name and flags.
 *
 * Only one implementation of RSA operations.
 * name is duplicated.
 *
 * @param [in] name   Name to use in method.
 * @param [in] flags  Flags to set into method.
 * @return  Newly allocated RSA method on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA_METHOD *wolfSSL_RSA_meth_new(const char *name, int flags)
{
    WOLFSSL_RSA_METHOD* meth = NULL;
    int name_len = 0;
    int err;

    /* Validate name is not NULL. */
    if (name == NULL)
        return NULL;
    /* Allocate an RSA METHOD to return. */
    meth = (WOLFSSL_RSA_METHOD*)XMALLOC(sizeof(WOLFSSL_RSA_METHOD), NULL,
                                        DYNAMIC_TYPE_OPENSSL);
    if (meth == NULL)
        return NULL;

    XMEMSET(meth, 0, sizeof(*meth));
    meth->flags = flags;
    meth->dynamic = 1;

    name_len = (int)XSTRLEN(name);
    meth->name = (char*)XMALLOC((size_t)(name_len + 1), NULL,
        DYNAMIC_TYPE_OPENSSL);
    err = (meth->name == NULL);

    if (!err) {
        XMEMCPY(meth->name, name, (size_t)(name_len + 1));
    }

    if (err) {
        /* meth->name won't be allocated on error. */
        XFREE(meth, NULL, DYNAMIC_TYPE_OPENSSL);
        meth = NULL;
    }
    return meth;
}

/* Default RSA method is one with wolfSSL name and no flags.
 *
 * @return  Newly allocated wolfSSL RSA method on success.
 * @return  NULL on failure.
 */
const WOLFSSL_RSA_METHOD* wolfSSL_RSA_get_default_method(void)
{
    static const WOLFSSL_RSA_METHOD wolfssl_rsa_meth = {
        0, /* No flags. */
        (char*)"wolfSSL RSA",
        0  /* Static definition. */
    };
    return &wolfssl_rsa_meth;
}

/* Dispose of RSA method and allocated data.
 *
 * @param [in] meth  RSA method to free.
 */
void wolfSSL_RSA_meth_free(WOLFSSL_RSA_METHOD *meth)
{
    /* Free method if available and dynamically allocated. */
    if ((meth != NULL) && meth->dynamic) {
        /* Name was duplicated and must be freed. */
        XFREE(meth->name, NULL, DYNAMIC_TYPE_OPENSSL);
        /* Dispose of RSA method. */
        XFREE(meth, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

#ifndef NO_WOLFSSL_STUB
/* Stub function for any RSA method setting function.
 *
 * Nothing is stored - not even flags or name.
 *
 * @param [in] meth  RSA method.
 * @param [in] p     A pointer.
 * @return  1 to indicate success.
 */
int wolfSSL_RSA_meth_set(WOLFSSL_RSA_METHOD *meth, void* p)
{
    WOLFSSL_STUB("RSA_METHOD is not implemented.");

    (void)meth;
    (void)p;

    return 1;
}
#endif /* !NO_WOLFSSL_STUB */
#endif /* OPENSSL_EXTRA */

/*
 * RSA constructor/deconstructor APIs
 */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Dispose of RSA key and allocated data.
 *
 * Cannot use rsa after this call.
 *
 * @param [in] rsa  RSA key to free.
 */
void wolfSSL_RSA_free(WOLFSSL_RSA* rsa)
{
    int doFree = 1;

    WOLFSSL_ENTER("wolfSSL_RSA_free");

    /* Validate parameter. */
    if (rsa == NULL) {
        doFree = 0;
    }
    if (doFree) {
        int err;

        /* Decrement reference count. */
        wolfSSL_RefDec(&rsa->ref, &doFree, &err);
    #ifndef WOLFSSL_REFCNT_ERROR_RETURN
        (void)err;
    #endif
    }
    if (doFree) {
        void* heap = rsa->heap;

        /* Dispose of allocated reference counting data. */
        wolfSSL_RefFree(&rsa->ref);

    #ifdef HAVE_EX_DATA_CLEANUP_HOOKS
        wolfSSL_CRYPTO_cleanup_ex_data(&rsa->ex_data);
    #endif

        if (rsa->internal != NULL) {
        #if !defined(HAVE_FIPS) && defined(WC_RSA_BLINDING)
            /* Check if RNG is owned before freeing it. */
            if (rsa->ownRng) {
                WC_RNG* rng = ((RsaKey*)(rsa->internal))->rng;
                if ((rng != NULL) && (rng != wolfssl_get_global_rng())) {
                    wc_FreeRng(rng);
                    XFREE(rng, heap, DYNAMIC_TYPE_RNG);
                }
                /* RNG isn't freed by wolfCrypt RSA free. */
            }
        #endif
            /* Dispose of allocated data in wolfCrypt RSA key. */
            wc_FreeRsaKey((RsaKey*)rsa->internal);
            /* Dispose of memory for wolfCrypt RSA key. */
            XFREE(rsa->internal, heap, DYNAMIC_TYPE_RSA);
        }

        /* Dispose of external representation of RSA values. */
        wolfSSL_BN_clear_free(rsa->iqmp);
        wolfSSL_BN_clear_free(rsa->dmq1);
        wolfSSL_BN_clear_free(rsa->dmp1);
        wolfSSL_BN_clear_free(rsa->q);
        wolfSSL_BN_clear_free(rsa->p);
        wolfSSL_BN_clear_free(rsa->d);
        wolfSSL_BN_free(rsa->e);
        wolfSSL_BN_free(rsa->n);

    #if defined(OPENSSL_EXTRA)
        if (rsa->meth) {
            wolfSSL_RSA_meth_free((WOLFSSL_RSA_METHOD*)rsa->meth);
        }
    #endif

        /* Set back to NULLs for safety. */
        ForceZero(rsa, sizeof(*rsa));

        XFREE(rsa, heap, DYNAMIC_TYPE_RSA);
        (void)heap;
    }
}

/* Allocate and initialize a new RSA key.
 *
 * Not OpenSSL API.
 *
 * @param [in] heap   Heap hint for dynamic memory allocation.
 * @param [in] devId  Device identifier value.
 * @return  RSA key on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA* wolfSSL_RSA_new_ex(void* heap, int devId)
{
    WOLFSSL_RSA* rsa = NULL;
    RsaKey* key = NULL;
    int err = 0;
    int rsaKeyInited = 0;

    WOLFSSL_ENTER("wolfSSL_RSA_new");

    /* Allocate memory for new wolfCrypt RSA key. */
    key = (RsaKey*)XMALLOC(sizeof(RsaKey), heap, DYNAMIC_TYPE_RSA);
    if (key == NULL) {
        WOLFSSL_ERROR_MSG("wolfSSL_RSA_new malloc RsaKey failure");
        err = 1;
    }
    if (!err) {
        /* Allocate memory for new RSA key. */
        rsa = (WOLFSSL_RSA*)XMALLOC(sizeof(WOLFSSL_RSA), heap,
            DYNAMIC_TYPE_RSA);
        if (rsa == NULL) {
            WOLFSSL_ERROR_MSG("wolfSSL_RSA_new malloc WOLFSSL_RSA failure");
            err = 1;
        }
    }
    if (!err) {
        /* Clear all fields of RSA key. */
        XMEMSET(rsa, 0, sizeof(WOLFSSL_RSA));
        /* Cache heap to use for all allocations. */
        rsa->heap = heap;
    #ifdef OPENSSL_EXTRA
        /* Always have a method set. */
        rsa->meth = wolfSSL_RSA_get_default_method();
    #endif

        /* Initialize reference counting. */
        wolfSSL_RefInit(&rsa->ref, &err);
#ifdef WOLFSSL_REFCNT_ERROR_RETURN
    }
    if (!err) {
#endif
        /* Initialize wolfCrypt RSA key. */
        if (wc_InitRsaKey_ex(key, heap, devId) != 0) {
            WOLFSSL_ERROR_MSG("InitRsaKey WOLFSSL_RSA failure");
            err = 1;
        }
        else {
            rsaKeyInited = 1;
        }
    }
    #if !defined(HAVE_FIPS) && defined(WC_RSA_BLINDING)
    if (!err) {
        WC_RNG* rng;

        /* Create a local RNG. */
        rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), heap, DYNAMIC_TYPE_RNG);
        if ((rng != NULL) && (wc_InitRng_ex(rng, heap, devId) != 0)) {
            WOLFSSL_MSG("InitRng failure, attempting to use global RNG");
            XFREE(rng, heap, DYNAMIC_TYPE_RNG);
            rng = NULL;
        }

        rsa->ownRng = 1;
        if (rng == NULL) {
            /* Get the wolfSSL global RNG - not thread safe. */
            rng = wolfssl_get_global_rng();
            rsa->ownRng = 0;
        }
        if (rng == NULL) {
            /* Couldn't create global either. */
            WOLFSSL_ERROR_MSG("wolfSSL_RSA_new no WC_RNG for blinding");
            err = 1;
        }
        else {
            /* Set the local or global RNG into the wolfCrypt RSA key. */
            (void)wc_RsaSetRNG(key, rng);
            /* Won't fail as key and rng are not NULL. */
        }
    }
    #endif /* !HAVE_FIPS && WC_RSA_BLINDING */
    if (!err) {
        /* Set wolfCrypt RSA key into RSA key. */
        rsa->internal = key;
        /* Data from external RSA key has not been set into internal one. */
        rsa->inSet = 0;
    }

    if (err) {
        /* Dispose of any allocated data on error. */
        /* No failure after RNG allocation - no need to free RNG. */
        if (rsaKeyInited) {
            wc_FreeRsaKey(key);
        }
        XFREE(key, heap, DYNAMIC_TYPE_RSA);
        XFREE(rsa, heap, DYNAMIC_TYPE_RSA);
        /* Return NULL. */
        rsa = NULL;
    }
    return rsa;
}

/* Allocate and initialize a new RSA key.
 *
 * @return  RSA key on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA* wolfSSL_RSA_new(void)
{
    /* Call wolfSSL API to do work. */
    return wolfSSL_RSA_new_ex(NULL, INVALID_DEVID);
}

/* Increments ref count of RSA key.
 *
 * @param [in, out] rsa  RSA key.
 * @return  1 on success
 * @return  0 on error
 */
int wolfSSL_RSA_up_ref(WOLFSSL_RSA* rsa)
{
    int err = 0;
    if (rsa != NULL) {
        wolfSSL_RefInc(&rsa->ref, &err);
    }
    return !err;
}

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA

#if defined(WOLFSSL_KEY_GEN)

/* Allocate a new RSA key and make it a copy.
 *
 * Encodes to and from DER to copy.
 *
 * @param [in] rsa  RSA key to duplicate.
 * @return  RSA key on success.
 * @return  NULL on error.
 */
WOLFSSL_RSA* wolfSSL_RSAPublicKey_dup(WOLFSSL_RSA *rsa)
{
    WOLFSSL_RSA* ret = NULL;
    int derSz = 0;
    byte* derBuf = NULL;
    int err;

    WOLFSSL_ENTER("wolfSSL_RSAPublicKey_dup");

    err = (rsa == NULL);
    if (!err) {
        /* Create a new RSA key to return. */
        ret = wolfSSL_RSA_new();
        if (ret == NULL) {
            WOLFSSL_ERROR_MSG("Error creating a new WOLFSSL_RSA structure");
            err = 1;
        }
    }
    if (!err) {
        /* Encode RSA public key to copy to DER - allocates DER buffer. */
        if ((derSz = wolfSSL_RSA_To_Der(rsa, &derBuf, 1, rsa->heap)) < 0) {
            WOLFSSL_ERROR_MSG("wolfSSL_RSA_To_Der failed");
            err = 1;
        }
    }
    if (!err) {
        /* Decode DER of the RSA public key into new key. */
        if (wolfSSL_RSA_LoadDer_ex(ret, derBuf, derSz,
                WOLFSSL_RSA_LOAD_PUBLIC) != 1) {
            WOLFSSL_ERROR_MSG("wolfSSL_RSA_LoadDer_ex failed");
            err = 1;
        }
    }

    /* Dispose of any allocated DER buffer. */
    XFREE(derBuf, rsa ? rsa->heap : NULL, DYNAMIC_TYPE_ASN1);
    if (err) {
        /* Disposes of any created RSA key - on error. */
        wolfSSL_RSA_free(ret);
        ret = NULL;
    }
    return ret;
}

/* wolfSSL_RSAPrivateKey_dup not supported */

#endif /* WOLFSSL_KEY_GEN */

static int wolfSSL_RSA_To_Der_ex(WOLFSSL_RSA* rsa, byte** outBuf, int publicKey,
    void* heap);

/*
 * RSA to/from bin APIs
 */

/* Convert RSA public key data to internal.
 *
 * Creates new RSA key from the DER encoded RSA public key.
 *
 * @param [out]     out      Pointer to RSA key to return through. May be NULL.
 * @param [in, out] derBuf   Pointer to start of DER encoded data.
 * @param [in]      derSz    Length of the data in the DER buffer.
 * @return  RSA key on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA *wolfSSL_d2i_RSAPublicKey(WOLFSSL_RSA **out,
    const unsigned char **derBuf, long derSz)
{
    WOLFSSL_RSA *rsa = NULL;
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_d2i_RSAPublicKey");

    /* Validate parameters. */
    if (derBuf == NULL) {
        WOLFSSL_ERROR_MSG("Bad argument");
        err = 1;
    }
    /* Create a new RSA key to return. */
    if ((!err) && ((rsa = wolfSSL_RSA_new()) == NULL)) {
        WOLFSSL_ERROR_MSG("RSA_new failed");
        err = 1;
    }
    /* Decode RSA key from DER. */
    if ((!err) && (wolfSSL_RSA_LoadDer_ex(rsa, *derBuf, (int)derSz,
            WOLFSSL_RSA_LOAD_PUBLIC) != 1)) {
        WOLFSSL_ERROR_MSG("RSA_LoadDer failed");
        err = 1;
    }
    if ((!err) && (out != NULL)) {
        /* Return through parameter too. */
        *out = rsa;
        /* Move buffer on by the used amount. */
        *derBuf += wolfssl_der_length(*derBuf, (int)derSz);
    }

    if (err) {
        /* Dispose of any created RSA key. */
        wolfSSL_RSA_free(rsa);
        rsa = NULL;
    }
    return rsa;
}

/* Convert RSA private key data to internal.
 *
 * Create a new RSA key from the DER encoded RSA private key.
 *
 * @param [out]     out      Pointer to RSA key to return through. May be NULL.
 * @param [in, out] derBuf   Pointer to start of DER encoded data.
 * @param [in]      derSz    Length of the data in the DER buffer.
 * @return  RSA key on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA *wolfSSL_d2i_RSAPrivateKey(WOLFSSL_RSA **out,
    const unsigned char **derBuf, long derSz)
{
    WOLFSSL_RSA *rsa = NULL;
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_d2i_RSAPublicKey");

    /* Validate parameters. */
    if (derBuf == NULL) {
        WOLFSSL_ERROR_MSG("Bad argument");
        err = 1;
    }
    /* Create a new RSA key to return. */
    if ((!err) && ((rsa = wolfSSL_RSA_new()) == NULL)) {
        WOLFSSL_ERROR_MSG("RSA_new failed");
        err = 1;
    }
    /* Decode RSA key from DER. */
    if ((!err) && (wolfSSL_RSA_LoadDer_ex(rsa, *derBuf, (int)derSz,
            WOLFSSL_RSA_LOAD_PRIVATE) != 1)) {
        WOLFSSL_ERROR_MSG("RSA_LoadDer failed");
        err = 1;
    }
    if ((!err) && (out != NULL)) {
        /* Return through parameter too. */
        *out = rsa;
        /* Move buffer on by the used amount. */
        *derBuf += wolfssl_der_length(*derBuf, (int)derSz);
    }

    if (err) {
        /* Dispose of any created RSA key. */
        wolfSSL_RSA_free(rsa);
        rsa = NULL;
    }
    return rsa;
}

/* Converts an internal RSA structure to DER format for the private key.
 *
 * If "pp" is null then buffer size only is returned.
 * If "*pp" is null then a created buffer is set in *pp and the caller is
 *  responsible for free'ing it.
 *
 * @param [in]      rsa  RSA key.
 * @param [in, out] pp   On in, pointer to allocated buffer or NULL.
 *                       May be NULL.
 *                       On out, newly allocated buffer or pointer to byte after
 *                       encoding in passed in buffer.
 *
 * @return  Size of DER encoding on success
 * @return  BAD_FUNC_ARG when rsa is NULL.
 * @return  0 on failure.
 */
int wolfSSL_i2d_RSAPrivateKey(WOLFSSL_RSA *rsa, unsigned char **pp)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_i2d_RSAPrivateKey");

    /* Validate parameters. */
    if (rsa == NULL) {
        WOLFSSL_ERROR_MSG("Bad Function Arguments");
        ret = BAD_FUNC_ARG;
    }
    /* Encode the RSA key as a DER. Call allocates buffer into pp.
     * No heap hint as this gets returned to the user */
    else if ((ret = wolfSSL_RSA_To_Der_ex(rsa, pp, 0, NULL)) < 0) {
        WOLFSSL_ERROR_MSG("wolfSSL_RSA_To_Der failed");
        ret = 0;
    }

    /* Size of DER encoding. */
    return ret;
}

/* Converts an internal RSA structure to DER format for the public key.
 *
 * If "pp" is null then buffer size only is returned.
 * If "*pp" is null then a created buffer is set in *pp and the caller is
 *  responsible for free'ing it.
 *
 * @param [in]      rsa  RSA key.
 * @param [in, out] pp   On in, pointer to allocated buffer or NULL.
 *                       May be NULL.
 *                       On out, newly allocated buffer or pointer to byte after
 *                       encoding in passed in buffer.
 * @return  Size of DER encoding on success
 * @return  BAD_FUNC_ARG when rsa is NULL.
 * @return  0 on failure.
 */
int wolfSSL_i2d_RSAPublicKey(WOLFSSL_RSA *rsa, unsigned char **pp)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_i2d_RSAPublicKey");

    /* check for bad functions arguments */
    if (rsa == NULL) {
        WOLFSSL_ERROR_MSG("Bad Function Arguments");
        ret = BAD_FUNC_ARG;
    }
    /* Encode the RSA key as a DER. Call allocates buffer into pp.
     * No heap hint as this gets returned to the user */
    else if ((ret = wolfSSL_RSA_To_Der_ex(rsa, pp, 1, NULL)) < 0) {
        WOLFSSL_ERROR_MSG("wolfSSL_RSA_To_Der failed");
        ret = 0;
    }

    return ret;
}

#endif /* OPENSSL_EXTRA */

/*
 * RSA to/from BIO APIs
 */

/* wolfSSL_d2i_RSAPublicKey_bio not supported */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX) || defined(WOLFSSL_QT)

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_BIO)

/* Read DER data from a BIO.
 *
 * DER structures start with a constructed sequence. Use this to calculate the
 * total length of the DER data.
 *
 * @param [in]  bio   BIO object to read from.
 * @param [out] out   Buffer holding DER encoding.
 * @return  Number of bytes to DER encoding on success.
 * @return  0 on failure.
 */
static int wolfssl_read_der_bio(WOLFSSL_BIO* bio, unsigned char** out)
{
    int err = 0;
    unsigned char seq[MAX_SEQ_SZ];
    unsigned char* der = NULL;
    int derLen = 0;

    /* Read in a minimal amount to get a SEQUENCE header of any size. */
    if (wolfSSL_BIO_read(bio, seq, sizeof(seq)) != sizeof(seq)) {
        WOLFSSL_ERROR_MSG("wolfSSL_BIO_read() of sequence failure");
        err = 1;
    }
    /* Calculate complete DER encoding length. */
    if ((!err) && ((derLen = wolfssl_der_length(seq, sizeof(seq))) <= 0)) {
        WOLFSSL_ERROR_MSG("DER SEQUENCE decode failed");
        err = 1;
    }
    /* Allocate a buffer to read DER data into. */
    if ((!err) && ((der = (unsigned char*)XMALLOC((size_t)derLen, bio->heap,
            DYNAMIC_TYPE_TMP_BUFFER)) == NULL)) {
        WOLFSSL_ERROR_MSG("Malloc failure");
        err = 1;
    }
    if ((!err) && (derLen <= (int)sizeof(seq))) {
        /* Copy the previously read data into the buffer. */
        XMEMCPY(der, seq, derLen);
    }
    else if (!err) {
        /* Calculate the unread amount. */
        int len = derLen - (int)sizeof(seq);
        /* Copy the previously read data into the buffer. */
        XMEMCPY(der, seq, sizeof(seq));
        /* Read rest of DER data from BIO. */
        if (wolfSSL_BIO_read(bio, der + sizeof(seq), len) != len) {
            WOLFSSL_ERROR_MSG("wolfSSL_BIO_read() failure");
            err = 1;
        }
    }
    if (!err) {
        /* Return buffer through parameter. */
        *out = der;
    }

    if (err) {
        /* Dispose of any allocated buffer on error. */
        XFREE(der, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
        derLen = 0;
    }
    return derLen;
}

/* Reads the RSA private key data from a BIO to the internal form.
 *
 * Creates new RSA key from the DER encoded RSA private key read from the BIO.
 *
 * @param [in]  bio  BIO object to read from.
 * @param [out] out  Pointer to RSA key to return through. May be NULL.
 * @return  RSA key on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA* wolfSSL_d2i_RSAPrivateKey_bio(WOLFSSL_BIO *bio, WOLFSSL_RSA **out)
{
    WOLFSSL_RSA* key = NULL;
    unsigned char* der = NULL;
    int derLen = 0;
    int err;

    WOLFSSL_ENTER("wolfSSL_d2i_RSAPrivateKey_bio");

    /* Validate parameters. */
    err = (bio == NULL);
    /* Read just DER encoding from BIO - buffer allocated in call. */
    if ((!err) && ((derLen = wolfssl_read_der_bio(bio, &der)) == 0)) {
        err = 1;
    }
    if (!err) {
        /* Keep der for call to deallocate. */
        const unsigned char* cder = der;
        /* Create an RSA key from the data from the BIO. */
        key = wolfSSL_d2i_RSAPrivateKey(NULL, &cder, derLen);
        err = (key == NULL);
    }
    if ((!err) && (out != NULL)) {
        /* Return the created RSA key through the parameter. */
        *out = key;
    }

    if (err) {
        /* Dispose of created key on error. */
        wolfSSL_RSA_free(key);
        key = NULL;
    }
    /* Dispose of allocated data. */
    XFREE(der, bio ? bio->heap : NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return key;
}
#endif /* defined(WOLFSSL_KEY_GEN) && !NO_BIO */

#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_QT */

/*
 * RSA DER APIs
 */

#ifdef OPENSSL_EXTRA

/* Create a DER encoding of key.
 *
 * Not OpenSSL API.
 *
 * @param [in]  rsa        RSA key.
 * @param [out] outBuf     Allocated buffer containing DER encoding.
 *                         May be NULL.
 * @param [in]  publicKey  Whether to encode as public key.
 * @param [in]  heap       Heap hint.
 * @return  Encoding size on success.
 * @return  Negative on failure.
 */
int wolfSSL_RSA_To_Der(WOLFSSL_RSA* rsa, byte** outBuf, int publicKey,
    void* heap)
{
    byte* p = NULL;
    int ret;

    if (outBuf != NULL) {
        p = *outBuf;
    }
    ret = wolfSSL_RSA_To_Der_ex(rsa, outBuf, publicKey, heap);
    if ((ret > 0) && (p != NULL)) {
        *outBuf = p;
    }
    return ret;
}

/* Create a DER encoding of key.
 *
 * Buffer allocated with heap and DYNAMIC_TYPE_TMP_BUFFER.
 *
 * @param [in]      rsa        RSA key.
 * @param [in, out] outBuf     On in, pointer to allocated buffer or NULL.
 *                             May be NULL.
 *                             On out, newly allocated buffer or pointer to byte
 *                             after encoding in passed in buffer.
 * @param [in]      publicKey  Whether to encode as public key.
 * @param [in]      heap       Heap hint.
 * @return  Encoding size on success.
 * @return  Negative on failure.
 */
static int wolfSSL_RSA_To_Der_ex(WOLFSSL_RSA* rsa, byte** outBuf, int publicKey,
    void* heap)
{
    int ret = 1;
    int derSz = 0;
    byte* derBuf = NULL;

    WOLFSSL_ENTER("wolfSSL_RSA_To_Der");

    /* Unused if memory is disabled. */
    (void)heap;

    /* Validate parameters. */
    if ((rsa == NULL) || ((publicKey != 0) && (publicKey != 1))) {
        WOLFSSL_LEAVE("wolfSSL_RSA_To_Der", BAD_FUNC_ARG);
        ret = BAD_FUNC_ARG;
    }
    /* Push external RSA data into internal RSA key if not set. */
    if ((ret == 1) && (!rsa->inSet)) {
        ret = SetRsaInternal(rsa);
    }
    /* wc_RsaKeyToPublicDer encode regardless of values. */
    if ((ret == 1) && publicKey && (mp_iszero(&((RsaKey*)rsa->internal)->n) ||
            mp_iszero(&((RsaKey*)rsa->internal)->e))) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 1) {
        if (publicKey) {
            /* Calculate length of DER encoded RSA public key. */
            derSz = wc_RsaPublicKeyDerSize((RsaKey*)rsa->internal, 1);
            if (derSz < 0) {
                WOLFSSL_ERROR_MSG("wc_RsaPublicKeyDerSize failed");
                ret = derSz;
            }
        }
        else {
            /* Calculate length of DER encoded RSA private key. */
            derSz = wc_RsaKeyToDer((RsaKey*)rsa->internal, NULL, 0);
            if (derSz < 0) {
                WOLFSSL_ERROR_MSG("wc_RsaKeyToDer failed");
                ret = derSz;
            }
        }
    }

    if ((ret == 1) && (outBuf != NULL)) {
        derBuf = *outBuf;
        if (derBuf == NULL) {
            /* Allocate buffer to hold DER encoded RSA key. */
            derBuf = (byte*)XMALLOC((size_t)derSz, heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (derBuf == NULL) {
                WOLFSSL_ERROR_MSG("Memory allocation failed");
                ret = MEMORY_ERROR;
            }
        }
    }
    if ((ret == 1) && (outBuf != NULL)) {
        if (publicKey > 0) {
            /* RSA public key to DER. */
            derSz = wc_RsaKeyToPublicDer((RsaKey*)rsa->internal, derBuf,
                (word32)derSz);
        }
        else {
            /* RSA private key to DER. */
            derSz = wc_RsaKeyToDer((RsaKey*)rsa->internal, derBuf,
                (word32)derSz);
        }
        if (derSz < 0) {
            WOLFSSL_ERROR_MSG("RSA key encoding failed");
            ret = derSz;
        }
        else if ((*outBuf) != NULL) {
            derBuf = NULL;
            *outBuf += derSz;
        }
        else {
            /* Return allocated buffer. */
            *outBuf = derBuf;
        }
    }
    if (ret == 1) {
        /* Success - return DER encoding size. */
        ret = derSz;
    }

    if ((outBuf != NULL) && (*outBuf != derBuf)) {
        /* Not returning buffer, needs to be disposed of. */
        XFREE(derBuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    WOLFSSL_LEAVE("wolfSSL_RSA_To_Der", ret);
    return ret;
}

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Load the DER encoded private RSA key.
 *
 * Not OpenSSL API.
 *
 * @param [in] rsa     RSA key.
 * @param [in] derBuf  Buffer holding DER encoding.
 * @param [in] derSz   Length of DER encoding.
 * @return  1 on success.
 * @return  -1 on failure.
 */
int wolfSSL_RSA_LoadDer(WOLFSSL_RSA* rsa, const unsigned char* derBuf,
    int derSz)
{
    /* Call implementation that handles both private and public keys. */
    return wolfSSL_RSA_LoadDer_ex(rsa, derBuf, derSz, WOLFSSL_RSA_LOAD_PRIVATE);
}

/* Load the DER encoded public or private RSA key.
 *
 * Not OpenSSL API.
 *
 * @param [in] rsa     RSA key.
 * @param [in] derBuf  Buffer holding DER encoding.
 * @param [in] derSz   Length of DER encoding.
 * @param [in] opt     Indicates public or private key.
 *                     (WOLFSSL_RSA_LOAD_PUBLIC or WOLFSSL_RSA_LOAD_PRIVATE)
 * @return  1 on success.
 * @return  -1 on failure.
 */
int wolfSSL_RSA_LoadDer_ex(WOLFSSL_RSA* rsa, const unsigned char* derBuf,
    int derSz, int opt)
{
    int ret = 1;
    int res;
    word32 idx = 0;
    word32 algId;

    WOLFSSL_ENTER("wolfSSL_RSA_LoadDer");

    /* Validate parameters. */
    if ((rsa == NULL) || (rsa->internal == NULL) || (derBuf == NULL) ||
            (derSz <= 0)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 1) {
        rsa->pkcs8HeaderSz = 0;
        /* Check if input buffer has PKCS8 header. In the case that it does not
         * have a PKCS8 header then do not error out. */
        res = ToTraditionalInline_ex((const byte*)derBuf, &idx, (word32)derSz,
            &algId);
        if (res > 0) {
            /* Store size of PKCS#8 header for encoding. */
            WOLFSSL_MSG("Found PKCS8 header");
            rsa->pkcs8HeaderSz = (word16)idx;
        }
        /* When decoding and not PKCS#8, return will be ASN_PARSE_E. */
        else if (res != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            /* Something went wrong while decoding. */
            WOLFSSL_ERROR_MSG("Unexpected error with trying to remove PKCS#8 "
                              "header");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 1) {
        /* Decode private or public key data. */
        if (opt == WOLFSSL_RSA_LOAD_PRIVATE) {
            res = wc_RsaPrivateKeyDecode(derBuf, &idx, (RsaKey*)rsa->internal,
                (word32)derSz);
        }
        else {
            res = wc_RsaPublicKeyDecode(derBuf, &idx, (RsaKey*)rsa->internal,
                (word32)derSz);
        }
        /* Check for error. */
        if (res < 0) {
            if (opt == WOLFSSL_RSA_LOAD_PRIVATE) {
                 WOLFSSL_ERROR_MSG("RsaPrivateKeyDecode failed");
            }
            else {
                 WOLFSSL_ERROR_MSG("RsaPublicKeyDecode failed");
            }
            WOLFSSL_ERROR_VERBOSE(res);
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 1) {
        /* Set external RSA key data from wolfCrypt key. */
        if (SetRsaExternal(rsa) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
        else {
            rsa->inSet = 1;
        }
    }

    return ret;
}

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)

#if !defined(NO_BIO) || !defined(NO_FILESYSTEM)
/* Load DER encoded data into WOLFSSL_RSA object.
 *
 * Creates a new WOLFSSL_RSA object if one is not passed in.
 *
 * @param [in, out] rsa   WOLFSSL_RSA object to load into.
 *                        When rsa or *rsa is NULL a new object is created.
 *                        When not NULL and *rsa is NULL then new object
 *                        returned through pointer.
 * @param [in]      in    DER encoded RSA key data.
 * @param [in]      inSz  Size of DER encoded data in bytes.
 * @param [in]      opt   Public or private key encoded in data. Valid values:
 *                        WOLFSSL_RSA_LOAD_PRIVATE, WOLFSSL_RSA_LOAD_PUBLIC.
 * @return  NULL on failure.
 * @return  WOLFSSL_RSA object on success.
 */
static WOLFSSL_RSA* wolfssl_rsa_d2i(WOLFSSL_RSA** rsa, const unsigned char* in,
    long inSz, int opt)
{
    WOLFSSL_RSA* ret = NULL;

    if ((rsa != NULL) && (*rsa != NULL)) {
        ret = *rsa;
    }
    else {
        ret = wolfSSL_RSA_new();
    }
    if ((ret != NULL) && (wolfSSL_RSA_LoadDer_ex(ret, in, (int)inSz, opt)
            != 1)) {
        if ((rsa == NULL) || (ret != *rsa)) {
            wolfSSL_RSA_free(ret);
        }
        ret = NULL;
    }

    if ((rsa != NULL) && (*rsa == NULL)) {
        *rsa = ret;
    }
    return ret;
}
#endif

#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

/*
 * RSA PEM APIs
 */

#ifdef OPENSSL_EXTRA

#ifndef NO_BIO
#if defined(WOLFSSL_KEY_GEN)
/* Writes PEM encoding of an RSA public key to a BIO.
 *
 * @param [in] bio  BIO object to write to.
 * @param [in] rsa  RSA key to write.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_bio_RSA_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa)
{
    int ret = 1;
    int derSz = 0;
    byte* derBuf = NULL;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_RSA_PUBKEY");

    /* Validate parameters. */
    if ((bio == NULL) || (rsa == NULL)) {
        WOLFSSL_ERROR_MSG("Bad Function Arguments");
        return 0;
    }

    if ((derSz = wolfSSL_RSA_To_Der(rsa, &derBuf, 1, bio->heap)) < 0) {
        WOLFSSL_ERROR_MSG("wolfSSL_RSA_To_Der failed");
        ret = 0;
    }
    if (derBuf == NULL) {
        WOLFSSL_ERROR_MSG("wolfSSL_RSA_To_Der failed to get buffer");
        ret = 0;
    }
    if ((ret == 1) && (der_write_to_bio_as_pem(derBuf, derSz, bio,
            PUBLICKEY_TYPE) != 1)) {
        ret = 0;
    }

    /* Dispose of DER buffer. */
    XFREE(derBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#endif /* WOLFSSL_KEY_GEN */
#endif /* !NO_BIO */

#if defined(WOLFSSL_KEY_GEN)
#ifndef NO_FILESYSTEM

/* Writes PEM encoding of an RSA public key to a file pointer.
 *
 * @param [in] fp    File pointer to write to.
 * @param [in] rsa   RSA key to write.
 * @param [in] type  PEM type to write out.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wolfssl_pem_write_rsa_public_key(XFILE fp, WOLFSSL_RSA* rsa,
    int type)
{
    int ret = 1;
    int derSz;
    byte* derBuf = NULL;

    /* Validate parameters. */
    if ((fp == XBADFILE) || (rsa == NULL)) {
        WOLFSSL_ERROR_MSG("Bad Function Arguments");
        return 0;
    }

    if ((derSz = wolfSSL_RSA_To_Der(rsa, &derBuf, 1, rsa->heap)) < 0) {
        WOLFSSL_ERROR_MSG("wolfSSL_RSA_To_Der failed");
        ret = 0;
    }
    if (derBuf == NULL) {
        WOLFSSL_ERROR_MSG("wolfSSL_RSA_To_Der failed to get buffer");
        ret = 0;
    }
    if ((ret == 1) && (der_write_to_file_as_pem(derBuf, derSz, fp, type,
            rsa->heap) != 1)) {
        ret = 0;
    }

    /* Dispose of DER buffer. */
    XFREE(derBuf, rsa->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* Writes PEM encoding of an RSA public key to a file pointer.
 *
 * Header/footer will contain: PUBLIC KEY
 *
 * @param [in] fp   File pointer to write to.
 * @param [in] rsa  RSA key to write.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_RSA_PUBKEY(XFILE fp, WOLFSSL_RSA* rsa)
{
    return wolfssl_pem_write_rsa_public_key(fp, rsa, PUBLICKEY_TYPE);
}

/* Writes PEM encoding of an RSA public key to a file pointer.
 *
 * Header/footer will contain: RSA PUBLIC KEY
 *
 * @param [in] fp   File pointer to write to.
 * @param [in] rsa  RSA key to write.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_RSAPublicKey(XFILE fp, WOLFSSL_RSA* rsa)
{
    return wolfssl_pem_write_rsa_public_key(fp, rsa, RSA_PUBLICKEY_TYPE);
}
#endif /* !NO_FILESYSTEM */
#endif /* WOLFSSL_KEY_GEN */

#ifndef NO_BIO
/* Create an RSA public key by reading the PEM encoded data from the BIO.
 *
 * @param [in]  bio   BIO object to read from.
 * @param [out] out   RSA key created.
 * @param [in]  cb    Password callback when PEM encrypted.
 * @param [in]  pass  NUL terminated string for passphrase when PEM encrypted.
 * @return  RSA key on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA *wolfSSL_PEM_read_bio_RSA_PUBKEY(WOLFSSL_BIO* bio,
    WOLFSSL_RSA** out, wc_pem_password_cb* cb, void *pass)
{
    WOLFSSL_RSA* rsa = NULL;
    DerBuffer*   der = NULL;
    int          keyFormat = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_RSA_PUBKEY");

    if ((bio != NULL) && (pem_read_bio_key(bio, cb, pass, PUBLICKEY_TYPE,
            &keyFormat, &der) >= 0)) {
        rsa = wolfssl_rsa_d2i(out, der->buffer, der->length,
            WOLFSSL_RSA_LOAD_PUBLIC);
        if (rsa == NULL) {
            WOLFSSL_ERROR_MSG("Error loading DER buffer into WOLFSSL_RSA");
        }
    }

    FreeDer(&der);
    if ((out != NULL) && (rsa != NULL)) {
        *out = rsa;
    }
    return rsa;
}

WOLFSSL_RSA *wolfSSL_d2i_RSA_PUBKEY_bio(WOLFSSL_BIO *bio, WOLFSSL_RSA **out)
{
    char* data = NULL;
    int dataSz = 0;
    int memAlloced = 0;
    WOLFSSL_RSA* rsa = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_RSA_PUBKEY_bio");

    if (bio == NULL)
        return NULL;

    if (wolfssl_read_bio(bio, &data, &dataSz, &memAlloced) != 0) {
        if (memAlloced)
            XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    rsa = wolfssl_rsa_d2i(out, (const unsigned char*)data, dataSz,
            WOLFSSL_RSA_LOAD_PUBLIC);
    if (memAlloced)
        XFREE(data, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return rsa;
}
#endif /* !NO_BIO */

#ifndef NO_FILESYSTEM
/* Create an RSA public key by reading the PEM encoded data from the BIO.
 *
 * Header/footer should contain: PUBLIC KEY
 * PEM decoder supports either 'RSA PUBLIC KEY' or 'PUBLIC KEY'.
 *
 * @param [in]  fp    File pointer to read from.
 * @param [out] out   RSA key created.
 * @param [in]  cb    Password callback when PEM encrypted.
 * @param [in]  pass  NUL terminated string for passphrase when PEM encrypted.
 * @return  RSA key on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA *wolfSSL_PEM_read_RSA_PUBKEY(XFILE fp,
    WOLFSSL_RSA** out, wc_pem_password_cb* cb, void *pass)
{
    WOLFSSL_RSA* rsa = NULL;
    DerBuffer*   der = NULL;
    int          keyFormat = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_RSA_PUBKEY");

    if ((fp != XBADFILE) && (pem_read_file_key(fp, cb, pass, PUBLICKEY_TYPE,
            &keyFormat, &der) >= 0)) {
        rsa = wolfssl_rsa_d2i(out, der->buffer, der->length,
            WOLFSSL_RSA_LOAD_PUBLIC);
        if (rsa == NULL) {
            WOLFSSL_ERROR_MSG("Error loading DER buffer into WOLFSSL_RSA");
        }
    }

    FreeDer(&der);
    if ((out != NULL) && (rsa != NULL)) {
        *out = rsa;
    }
    return rsa;
}

/* Create an RSA public key by reading the PEM encoded data from the BIO.
 *
 * Header/footer should contain: RSA PUBLIC KEY
 * PEM decoder supports either 'RSA PUBLIC KEY' or 'PUBLIC KEY'.
 *
 * @param [in]  fp    File pointer to read from.
 * @param [out] rsa   RSA key created.
 * @param [in]  cb    Password callback when PEM encrypted. May be NULL.
 * @param [in]  pass  NUL terminated string for passphrase when PEM encrypted.
 *                    May be NULL.
 * @return  RSA key on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA* wolfSSL_PEM_read_RSAPublicKey(XFILE fp, WOLFSSL_RSA** rsa,
    wc_pem_password_cb* cb, void* pass)
{
    return wolfSSL_PEM_read_RSA_PUBKEY(fp, rsa, cb, pass);
}

#endif /* NO_FILESYSTEM */

#if defined(WOLFSSL_KEY_GEN) && \
    (defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM))

/* Writes PEM encoding of an RSA private key to newly allocated buffer.
 *
 * Buffer returned was allocated with: DYNAMIC_TYPE_KEY.
 *
 * @param [in]  rsa       RSA key to write.
 * @param [in]  cipher    Cipher to use when PEM encrypted. May be NULL.
 * @param [in]  passwd    Password string when PEM encrypted. May be NULL.
 * @param [in]  passwdSz  Length of password string when PEM encrypted.
 * @param [out] pem       Allocated buffer with PEM encoding.
 * @param [out] pLen      Length of PEM encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_mem_RSAPrivateKey(WOLFSSL_RSA* rsa,
    const WOLFSSL_EVP_CIPHER* cipher, unsigned char* passwd, int passwdSz,
    unsigned char **pem, int *pLen)
{
    int ret = 1;
    byte* derBuf = NULL;
    int  derSz = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_write_mem_RSAPrivateKey");

    /* Validate parameters. */
    if ((pem == NULL) || (pLen == NULL) || (rsa == NULL) ||
            (rsa->internal == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = 0;
    }

    /* Set the RSA key data into the wolfCrypt RSA key if not done so. */
    if ((ret == 1) && (!rsa->inSet) && (SetRsaInternal(rsa) != 1)) {
        ret = 0;
    }

    /* Encode wolfCrypt RSA key to DER - derBuf allocated in call. */
    if ((ret == 1) && ((derSz = wolfSSL_RSA_To_Der(rsa, &derBuf, 0,
            rsa->heap)) < 0)) {
        WOLFSSL_ERROR_MSG("wolfSSL_RSA_To_Der failed");
        ret = 0;
    }

    if ((ret == 1) && (der_to_enc_pem_alloc(derBuf, derSz, cipher, passwd,
            passwdSz, PRIVATEKEY_TYPE, NULL, pem, pLen) != 1)) {
        WOLFSSL_ERROR_MSG("der_to_enc_pem_alloc failed");
        ret = 0;
    }

    return ret;
}

#ifndef NO_BIO
/* Writes PEM encoding of an RSA private key to a BIO.
 *
 * @param [in] bio     BIO object to write to.
 * @param [in] rsa     RSA key to write.
 * @param [in] cipher  Cipher to use when PEM encrypted.
 * @param [in] passwd  Password string when PEM encrypted.
 * @param [in] len     Length of password string when PEM encrypted.
 * @param [in] cb      Password callback to use when PEM encrypted.
 * @param [in] arg     NUL terminated string for passphrase when PEM encrypted.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_bio_RSAPrivateKey(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa,
    const WOLFSSL_EVP_CIPHER* cipher, unsigned char* passwd, int len,
    wc_pem_password_cb* cb, void* arg)
{
    int ret = 1;
    byte* pem = NULL;
    int pLen = 0;

    (void)cb;
    (void)arg;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_RSAPrivateKey");

    /* Validate parameters. */
    if ((bio == NULL) || (rsa == NULL) || (rsa->internal == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = 0;
    }

    if (ret == 1) {
        /* Write PEM to buffer that is allocated in the call. */
        ret = wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, cipher, passwd, len,
            &pem, &pLen);
        if (ret != 1) {
            WOLFSSL_ERROR_MSG("wolfSSL_PEM_write_mem_RSAPrivateKey failed");
        }
    }
    /* Write PEM to BIO. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, pem, pLen) <= 0)) {
        WOLFSSL_ERROR_MSG("RSA private key BIO write failed");
        ret = 0;
    }

    /* Dispose of any allocated PEM buffer. */
    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    return ret;
}
#endif /* !NO_BIO */

#ifndef NO_FILESYSTEM
/* Writes PEM encoding of an RSA private key to a file pointer.
 *
 * TODO: Support use of the password callback and callback context.
 *
 * @param [in] fp        File pointer to write to.
 * @param [in] rsa       RSA key to write.
 * @param [in] cipher    Cipher to use when PEM encrypted. May be NULL.
 * @param [in] passwd    Password string when PEM encrypted. May be NULL.
 * @param [in] passwdSz  Length of password string when PEM encrypted.
 * @param [in] cb        Password callback to use when PEM encrypted. Unused.
 * @param [in] arg       NUL terminated string for passphrase when PEM
 *                       encrypted. Unused.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_RSAPrivateKey(XFILE fp, WOLFSSL_RSA *rsa,
    const WOLFSSL_EVP_CIPHER *cipher, unsigned char *passwd, int passwdSz,
    wc_pem_password_cb *cb, void *arg)
{
    int ret = 1;
    byte* pem = NULL;
    int pLen = 0;

    (void)cb;
    (void)arg;

    WOLFSSL_ENTER("wolfSSL_PEM_write_RSAPrivateKey");

    /* Validate parameters. */
    if ((fp == XBADFILE) || (rsa == NULL) || (rsa->internal == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = 0;
    }

    if (ret == 1) {
        /* Write PEM to buffer that is allocated in the call. */
        ret = wolfSSL_PEM_write_mem_RSAPrivateKey(rsa, cipher, passwd, passwdSz,
            &pem, &pLen);
        if (ret != 1) {
            WOLFSSL_ERROR_MSG("wolfSSL_PEM_write_mem_RSAPrivateKey failed");
        }
    }
    /* Write PEM to file pointer. */
    if ((ret == 1) && ((int)XFWRITE(pem, 1, (size_t)pLen, fp) != pLen)) {
        WOLFSSL_ERROR_MSG("RSA private key file write failed");
        ret = 0;
    }

    /* Dispose of any allocated PEM buffer. */
    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    return ret;
}
#endif /* NO_FILESYSTEM */
#endif /* WOLFSSL_KEY_GEN && WOLFSSL_PEM_TO_DER */

#ifndef NO_BIO
/* Create an RSA private key by reading the PEM encoded data from the BIO.
 *
 * @param [in]  bio   BIO object to read from.
 * @param [out] out   RSA key created.
 * @param [in]  cb    Password callback when PEM encrypted.
 * @param [in]  pass  NUL terminated string for passphrase when PEM encrypted.
 * @return  RSA key on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA* wolfSSL_PEM_read_bio_RSAPrivateKey(WOLFSSL_BIO* bio,
    WOLFSSL_RSA** out, wc_pem_password_cb* cb, void* pass)
{
    WOLFSSL_RSA* rsa = NULL;
    DerBuffer*   der = NULL;
    int          keyFormat = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_RSAPrivateKey");

    if ((bio != NULL) && (pem_read_bio_key(bio, cb, pass, PRIVATEKEY_TYPE,
            &keyFormat, &der) >= 0)) {
        rsa = wolfssl_rsa_d2i(out, der->buffer, der->length,
            WOLFSSL_RSA_LOAD_PRIVATE);
        if (rsa == NULL) {
            WOLFSSL_ERROR_MSG("Error loading DER buffer into WOLFSSL_RSA");
        }
    }

    FreeDer(&der);
    if ((out != NULL) && (rsa != NULL)) {
        *out = rsa;
    }
    return rsa;
}
#endif /* !NO_BIO */

/* Create an RSA private key by reading the PEM encoded data from the file
 * pointer.
 *
 * @param [in]  fp    File pointer to read from.
 * @param [out] out   RSA key created.
 * @param [in]  cb    Password callback when PEM encrypted.
 * @param [in]  pass  NUL terminated string for passphrase when PEM encrypted.
 * @return  RSA key on success.
 * @return  NULL on failure.
 */
#ifndef NO_FILESYSTEM
WOLFSSL_RSA* wolfSSL_PEM_read_RSAPrivateKey(XFILE fp, WOLFSSL_RSA** out,
    wc_pem_password_cb* cb, void* pass)
{
    WOLFSSL_RSA* rsa = NULL;
    DerBuffer*   der = NULL;
    int          keyFormat = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_RSAPrivateKey");

    if ((fp != XBADFILE) && (pem_read_file_key(fp, cb, pass, PRIVATEKEY_TYPE,
            &keyFormat, &der) >= 0)) {
        rsa = wolfssl_rsa_d2i(out, der->buffer, der->length,
            WOLFSSL_RSA_LOAD_PRIVATE);
        if (rsa == NULL) {
            WOLFSSL_ERROR_MSG("Error loading DER buffer into WOLFSSL_RSA");
        }
    }

    FreeDer(&der);
    if ((out != NULL) && (rsa != NULL)) {
        *out = rsa;
    }
    return rsa;
}
#endif /* !NO_FILESYSTEM */

/*
 * RSA print APIs
 */

#if defined(XFPRINTF) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM)
/* Print an RSA key to a file pointer.
 *
 * @param [in] fp      File pointer to write to.
 * @param [in] rsa     RSA key to write.
 * @param [in] indent  Number of spaces to prepend to each line.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_print_fp(XFILE fp, WOLFSSL_RSA* rsa, int indent)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_RSA_print_fp");

    /* Validate parameters. */
    if ((fp == XBADFILE) || (rsa == NULL)) {
        ret = 0;
    }

    /* Set the external data from the wolfCrypt RSA key if not done. */
    if ((ret == 1) && (!rsa->exSet)) {
        ret = SetRsaExternal(rsa);
    }

    /* Get the key size from modulus if available. */
    if ((ret == 1) && (rsa->n != NULL)) {
        int keySize = wolfSSL_BN_num_bits(rsa->n);
        if (keySize == 0) {
            ret = 0;
        }
        else {
            if (XFPRINTF(fp, "%*s", indent, "") < 0)
                ret = 0;
            else if (XFPRINTF(fp, "RSA Private-Key: (%d bit, 2 primes)\n",
                              keySize) < 0)
                ret = 0;
        }
    }
    /* Print out any components available. */
    if ((ret == 1) && (rsa->n != NULL)) {
        ret = pk_bn_field_print_fp(fp, indent, "modulus", rsa->n);
    }
    if ((ret == 1) && (rsa->d != NULL)) {
        ret = pk_bn_field_print_fp(fp, indent, "privateExponent", rsa->d);
    }
    if ((ret == 1) && (rsa->p != NULL)) {
        ret = pk_bn_field_print_fp(fp, indent, "prime1", rsa->p);
    }
    if ((ret == 1) && (rsa->q != NULL)) {
        ret = pk_bn_field_print_fp(fp, indent, "prime2", rsa->q);
    }
    if ((ret == 1) && (rsa->dmp1 != NULL)) {
        ret = pk_bn_field_print_fp(fp, indent, "exponent1", rsa->dmp1);
    }
    if ((ret == 1) && (rsa->dmq1 != NULL)) {
        ret = pk_bn_field_print_fp(fp, indent, "exponent2", rsa->dmq1);
    }
    if ((ret == 1) && (rsa->iqmp != NULL)) {
        ret = pk_bn_field_print_fp(fp, indent, "coefficient", rsa->iqmp);
    }

    WOLFSSL_LEAVE("wolfSSL_RSA_print_fp", ret);

    return ret;
}
#endif /* XFPRINTF && !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM */

#if defined(XSNPRINTF) && !defined(NO_BIO)
/* snprintf() must be available */

/* Maximum size of a header line. */
#define RSA_PRINT_MAX_HEADER_LINE   PRINT_NUM_MAX_INDENT

/* Writes the human readable form of RSA to a BIO.
 *
 * @param [in] bio     BIO object to write to.
 * @param [in] rsa     RSA key to write.
 * @param [in] indent  Number of spaces before each line.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_print(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa, int indent)
{
    int ret = 1;
    int sz = 0;
    RsaKey* key = NULL;
    char line[RSA_PRINT_MAX_HEADER_LINE];
    int i = 0;
    mp_int *num = NULL;
    /* Header strings. */
    const char *name[] = {
        "Modulus:", "Exponent:", "PrivateExponent:", "Prime1:", "Prime2:",
        "Exponent1:", "Exponent2:", "Coefficient:"
    };

    WOLFSSL_ENTER("wolfSSL_RSA_print");

    /* Validate parameters. */
    if ((bio == NULL) || (rsa == NULL) || (indent > PRINT_NUM_MAX_INDENT)) {
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 1) {
        key = (RsaKey*)rsa->internal;

        /* Get size in bits of key for printing out. */
        sz = wolfSSL_RSA_bits(rsa);
        if (sz <= 0) {
            WOLFSSL_ERROR_MSG("Error getting RSA key size");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Print any indent spaces. */
        ret = wolfssl_print_indent(bio, line, sizeof(line), indent);
    }
    if (ret == 1) {
        /* Print header line. */
        int len = XSNPRINTF(line, sizeof(line), "\nRSA %s: (%d bit)\n",
            (!mp_iszero(&key->d)) ? "Private-Key" : "Public-Key", sz);
        if (len >= (int)sizeof(line)) {
            WOLFSSL_ERROR_MSG("Buffer overflow while formatting key preamble");
            ret = 0;
        }
        else {
            if (wolfSSL_BIO_write(bio, line, len) <= 0) {
                ret = 0;
            }
        }
    }

    for (i = 0; (ret == 1) && (i < RSA_INTS); i++) {
        /* Get mp_int for index. */
        switch (i) {
            case 0:
                /* Print out modulus */
                num = &key->n;
                break;
            case 1:
                num = &key->e;
                break;
            case 2:
                num = &key->d;
                break;
            case 3:
                num = &key->p;
                break;
            case 4:
                num = &key->q;
                break;
            case 5:
                num = &key->dP;
                break;
            case 6:
                num = &key->dQ;
                break;
            case 7:
                num = &key->u;
                break;
            default:
                WOLFSSL_ERROR_MSG("Bad index value");
        }

        if (i == 1) {
            /* Print exponent as a 32-bit value. */
            ret = wolfssl_print_value(bio, num, name[i], indent);
        }
        else if (!mp_iszero(num)) {
            /* Print name and MP integer. */
            ret = wolfssl_print_number(bio, num, name[i], indent);
        }
    }

    return ret;
}
#endif /* XSNPRINTF && !NO_BIO */

#endif /* OPENSSL_EXTRA */

/*
 * RSA get/set/test APIs
 */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* Set RSA key data (external) from wolfCrypt RSA key (internal).
 *
 * @param [in, out] rsa  RSA key.
 * @return  1 on success.
 * @return  0 on failure.
 */
int SetRsaExternal(WOLFSSL_RSA* rsa)
{
    int ret = 1;

    WOLFSSL_ENTER("SetRsaExternal");

    /* Validate parameters. */
    if ((rsa == NULL) || (rsa->internal == NULL)) {
        WOLFSSL_ERROR_MSG("rsa key NULL error");
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 1) {
        RsaKey* key = (RsaKey*)rsa->internal;

        /* Copy modulus. */
        ret = wolfssl_bn_set_value(&rsa->n, &key->n);
        if (ret != 1) {
            WOLFSSL_ERROR_MSG("rsa n error");
        }
        if (ret == 1) {
            /* Copy public exponent. */
            ret = wolfssl_bn_set_value(&rsa->e, &key->e);
            if (ret != 1) {
                WOLFSSL_ERROR_MSG("rsa e error");
            }
        }

        if (key->type == RSA_PRIVATE) {
    #ifndef WOLFSSL_RSA_PUBLIC_ONLY
            if (ret == 1) {
                /* Copy private exponent. */
                ret = wolfssl_bn_set_value(&rsa->d, &key->d);
                if (ret != 1) {
                    WOLFSSL_ERROR_MSG("rsa d error");
                }
            }
            if (ret == 1) {
                /* Copy first prime. */
                ret = wolfssl_bn_set_value(&rsa->p, &key->p);
                if (ret != 1) {
                    WOLFSSL_ERROR_MSG("rsa p error");
                }
            }
            if (ret == 1) {
                /* Copy second prime. */
                ret = wolfssl_bn_set_value(&rsa->q, &key->q);
                if (ret != 1) {
                    WOLFSSL_ERROR_MSG("rsa q error");
                }
            }
        #if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || \
            !defined(RSA_LOW_MEM)
            if (ret == 1) {
                /* Copy d mod p-1. */
                ret = wolfssl_bn_set_value(&rsa->dmp1, &key->dP);
                if (ret != 1) {
                    WOLFSSL_ERROR_MSG("rsa dP error");
                }
            }
            if (ret == 1) {
                /* Copy d mod q-1. */
                ret = wolfssl_bn_set_value(&rsa->dmq1, &key->dQ);
                if (ret != 1) {
                    WOLFSSL_ERROR_MSG("rsa dq error");
                }
            }
            if (ret == 1) {
                /* Copy 1/q mod p. */
                ret = wolfssl_bn_set_value(&rsa->iqmp, &key->u);
                if (ret != 1) {
                    WOLFSSL_ERROR_MSG("rsa u error");
                }
            }
        #endif
    #else
            WOLFSSL_ERROR_MSG("rsa private key not compiled in ");
            ret = 0;
    #endif /* !WOLFSSL_RSA_PUBLIC_ONLY */
        }
    }
    if (ret == 1) {
        /* External values set. */
        rsa->exSet = 1;
    }
    else {
        /* Return 0 on failure. */
        ret = 0;
    }

    return ret;
}
#endif /* (OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL) */

#ifdef OPENSSL_EXTRA

/* Set wolfCrypt RSA key data (internal) from RSA key (external).
 *
 * @param [in, out] rsa  RSA key.
 * @return  1 on success.
 * @return  0 on failure.
 */
int SetRsaInternal(WOLFSSL_RSA* rsa)
{
    int ret = 1;

    WOLFSSL_ENTER("SetRsaInternal");

    /* Validate parameters. */
    if ((rsa == NULL) || (rsa->internal == NULL)) {
        WOLFSSL_ERROR_MSG("rsa key NULL error");
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 1) {
        RsaKey* key = (RsaKey*)rsa->internal;

        /* Copy down modulus if available. */
        if ((rsa->n != NULL) && (wolfssl_bn_get_value(rsa->n, &key->n) != 1)) {
            WOLFSSL_ERROR_MSG("rsa n key error");
            ret = WOLFSSL_FATAL_ERROR;
        }

        /* Copy down public exponent if available. */
        if ((ret == 1) && (rsa->e != NULL) &&
                (wolfssl_bn_get_value(rsa->e, &key->e) != 1)) {
            WOLFSSL_ERROR_MSG("rsa e key error");
            ret = WOLFSSL_FATAL_ERROR;
        }

        /* Enough numbers for public key */
        key->type = RSA_PUBLIC;

#ifndef WOLFSSL_RSA_PUBLIC_ONLY
        /* Copy down private exponent if available. */
        if ((ret == 1) && (rsa->d != NULL)) {
            if (wolfssl_bn_get_value(rsa->d, &key->d) != 1) {
                WOLFSSL_ERROR_MSG("rsa d key error");
                ret = WOLFSSL_FATAL_ERROR;
            }
            else {
                /* Enough numbers for private key */
                key->type = RSA_PRIVATE;
           }
        }

        /* Copy down first prime if available. */
        if ((ret == 1) && (rsa->p != NULL) &&
                (wolfssl_bn_get_value(rsa->p, &key->p) != 1)) {
            WOLFSSL_ERROR_MSG("rsa p key error");
            ret = WOLFSSL_FATAL_ERROR;
        }

        /* Copy down second prime if available. */
        if ((ret == 1) && (rsa->q != NULL) &&
                (wolfssl_bn_get_value(rsa->q, &key->q) != 1)) {
            WOLFSSL_ERROR_MSG("rsa q key error");
            ret = WOLFSSL_FATAL_ERROR;
        }

#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
        /* Copy down d mod p-1 if available. */
        if ((ret == 1) && (rsa->dmp1 != NULL) &&
                (wolfssl_bn_get_value(rsa->dmp1, &key->dP) != 1)) {
            WOLFSSL_ERROR_MSG("rsa dP key error");
            ret = WOLFSSL_FATAL_ERROR;
        }

        /* Copy down d mod q-1 if available. */
        if ((ret == 1) && (rsa->dmq1 != NULL) &&
                (wolfssl_bn_get_value(rsa->dmq1, &key->dQ) != 1)) {
            WOLFSSL_ERROR_MSG("rsa dQ key error");
            ret = WOLFSSL_FATAL_ERROR;
        }

        /* Copy down 1/q mod p if available. */
        if ((ret == 1) && (rsa->iqmp != NULL) &&
                (wolfssl_bn_get_value(rsa->iqmp, &key->u) != 1)) {
            WOLFSSL_ERROR_MSG("rsa u key error");
            ret = WOLFSSL_FATAL_ERROR;
        }
#endif
#endif

        if (ret == 1) {
            /* All available numbers have been set down. */
            rsa->inSet = 1;
        }
    }

    return ret;
}

/* Set the RSA method into object.
 *
 * @param [in, out] rsa   RSA key.
 * @param [in]      meth  RSA method.
 * @return  1 always.
 */
int wolfSSL_RSA_set_method(WOLFSSL_RSA *rsa, WOLFSSL_RSA_METHOD *meth)
{
    if (rsa != NULL) {
        /* Store the method into object. */
        rsa->meth = meth;
        /* Copy over flags. */
        rsa->flags = meth->flags;
    }
    /* OpenSSL always assumes it will work. */
    return 1;
}

/* Get the RSA method from the RSA object.
 *
 * @param [in] rsa  RSA key.
 * @return  RSA method on success.
 * @return  NULL when RSA is NULL or no method set.
 */
const WOLFSSL_RSA_METHOD* wolfSSL_RSA_get_method(const WOLFSSL_RSA *rsa)
{
    return (rsa != NULL) ? rsa->meth : NULL;
}

/* Get the size in bytes of the RSA key.
 *
 * Return compliant with OpenSSL
 *
 * @param [in] rsa  RSA key.
 * @return  RSA modulus size in bytes.
 * @return  0 on error.
 */
int wolfSSL_RSA_size(const WOLFSSL_RSA* rsa)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_RSA_size");

    if (rsa != NULL) {
        /* Make sure we have set the RSA values into wolfCrypt RSA key. */
        if (rsa->inSet || (SetRsaInternal((WOLFSSL_RSA*)rsa) == 1)) {
            /* Get key size in bytes using wolfCrypt RSA key. */
            ret = wc_RsaEncryptSize((RsaKey*)rsa->internal);
        }
    }

    return ret;
}

/* Get the size in bits of the RSA key.
 *
 * Uses external modulus field.
 *
 * @param [in] rsa  RSA key.
 * @return  RSA modulus size in bits.
 * @return  0 on error.
 */
int wolfSSL_RSA_bits(const WOLFSSL_RSA* rsa)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_RSA_bits");

    if (rsa != NULL) {
        /* Get number of bits in external modulus. */
        ret = wolfSSL_BN_num_bits(rsa->n);
    }

    return ret;
}

/* Get the BN objects that are the Chinese-Remainder Theorem (CRT) parameters.
 *
 * Only for those that are not NULL parameters.
 *
 * @param [in]  rsa   RSA key.
 * @param [out] dmp1  BN that is d mod (p - 1). May be NULL.
 * @param [out] dmq1  BN that is d mod (q - 1). May be NULL.
 * @param [out] iqmp  BN that is 1/q mod p. May be NULL.
 */
void wolfSSL_RSA_get0_crt_params(const WOLFSSL_RSA *rsa,
    const WOLFSSL_BIGNUM **dmp1, const WOLFSSL_BIGNUM **dmq1,
    const WOLFSSL_BIGNUM **iqmp)
{
    WOLFSSL_ENTER("wolfSSL_RSA_get0_crt_params");

    /* For any parameters not NULL, return the BN from the key or NULL. */
    if (dmp1 != NULL) {
        *dmp1 = (rsa != NULL) ? rsa->dmp1 : NULL;
    }
    if (dmq1 != NULL) {
        *dmq1 = (rsa != NULL) ? rsa->dmq1 : NULL;
    }
    if (iqmp != NULL) {
        *iqmp = (rsa != NULL) ? rsa->iqmp : NULL;
    }
}

/* Set the BN objects that are the Chinese-Remainder Theorem (CRT) parameters
 * into RSA key.
 *
 * If CRT parameter is NULL then there must be one in the RSA key already.
 *
 * @param [in, out] rsa   RSA key.
 * @param [in]      dmp1  BN that is d mod (p - 1). May be NULL.
 * @param [in]      dmq1  BN that is d mod (q - 1). May be NULL.
 * @param [in]      iqmp  BN that is 1/q mod p. May be NULL.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_set0_crt_params(WOLFSSL_RSA *rsa, WOLFSSL_BIGNUM *dmp1,
                                WOLFSSL_BIGNUM *dmq1, WOLFSSL_BIGNUM *iqmp)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_RSA_set0_crt_params");

    /* If a param is NULL in rsa then it must be non-NULL in the
     * corresponding user input. */
    if ((rsa == NULL) || ((rsa->dmp1 == NULL) && (dmp1 == NULL)) ||
            ((rsa->dmq1 == NULL) && (dmq1 == NULL)) ||
            ((rsa->iqmp == NULL) && (iqmp == NULL))) {
        WOLFSSL_ERROR_MSG("Bad parameters");
        ret = 0;
    }
    if (ret == 1) {
        /* Replace the BNs. */
        if (dmp1 != NULL) {
            wolfSSL_BN_clear_free(rsa->dmp1);
            rsa->dmp1 = dmp1;
        }
        if (dmq1 != NULL) {
            wolfSSL_BN_clear_free(rsa->dmq1);
            rsa->dmq1 = dmq1;
        }
        if (iqmp != NULL) {
            wolfSSL_BN_clear_free(rsa->iqmp);
            rsa->iqmp = iqmp;
        }

        /* Set the values into the wolfCrypt RSA key. */
        if (SetRsaInternal(rsa) != 1) {
            if (dmp1 != NULL) {
                rsa->dmp1 = NULL;
            }
            if (dmq1 != NULL) {
                rsa->dmq1 = NULL;
            }
            if (iqmp != NULL) {
                rsa->iqmp = NULL;
            }
            ret = 0;
        }
    }

    return ret;
}

/* Get the BN objects that are the factors of the RSA key (two primes p and q).
 *
 * @param [in]  rsa  RSA key.
 * @param [out] p    BN that is first prime. May be NULL.
 * @param [out] q    BN that is second prime. May be NULL.
 */
void wolfSSL_RSA_get0_factors(const WOLFSSL_RSA *rsa, const WOLFSSL_BIGNUM **p,
                              const WOLFSSL_BIGNUM **q)
{
    WOLFSSL_ENTER("wolfSSL_RSA_get0_factors");

    /* For any primes not NULL, return the BN from the key or NULL. */
    if (p != NULL) {
        *p = (rsa != NULL) ? rsa->p : NULL;
    }
    if (q != NULL) {
        *q = (rsa != NULL) ? rsa->q : NULL;
    }
}

/* Set the BN objects that are the factors of the RSA key (two primes p and q).
 *
 * If factor parameter is NULL then there must be one in the RSA key already.
 *
 * @param [in, out] rsa  RSA key.
 * @param [in]      p    BN that is first prime. May be NULL.
 * @param [in]      q    BN that is second prime. May be NULL.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_set0_factors(WOLFSSL_RSA *rsa, WOLFSSL_BIGNUM *p,
    WOLFSSL_BIGNUM *q)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_RSA_set0_factors");

    /* If a param is null in r then it must be non-null in the
     * corresponding user input. */
    if (rsa == NULL || ((rsa->p == NULL) && (p == NULL)) ||
            ((rsa->q == NULL) && (q == NULL))) {
        WOLFSSL_ERROR_MSG("Bad parameters");
        ret = 0;
    }
    if (ret == 1) {
        /* Replace the BNs. */
        if (p != NULL) {
            wolfSSL_BN_clear_free(rsa->p);
            rsa->p = p;
        }
        if (q != NULL) {
            wolfSSL_BN_clear_free(rsa->q);
            rsa->q = q;
        }

        /* Set the values into the wolfCrypt RSA key. */
        if (SetRsaInternal(rsa) != 1) {
             if (p != NULL) {
                 rsa->p = NULL;
             }
             if (q != NULL) {
                 rsa->q = NULL;
             }
             ret = 0;
        }
    }

    return ret;
}

/* Get the BN objects for the basic key numbers of the RSA key (modulus, public
 * exponent, private exponent).
 *
 * @param [in]  rsa  RSA key.
 * @param [out] n    BN that is the modulus. May be NULL.
 * @param [out] e    BN that is the public exponent. May be NULL.
 * @param [out] d    BN that is the private exponent. May be NULL.
 */
void wolfSSL_RSA_get0_key(const WOLFSSL_RSA *rsa, const WOLFSSL_BIGNUM **n,
    const WOLFSSL_BIGNUM **e, const WOLFSSL_BIGNUM **d)
{
    WOLFSSL_ENTER("wolfSSL_RSA_get0_key");

    /* For any parameters not NULL, return the BN from the key or NULL. */
    if (n != NULL) {
        *n = (rsa != NULL) ? rsa->n : NULL;
    }
    if (e != NULL) {
        *e = (rsa != NULL) ? rsa->e : NULL;
    }
    if (d != NULL) {
        *d = (rsa != NULL) ? rsa->d : NULL;
    }
}

/* Set the BN objects for the basic key numbers into the RSA key (modulus,
 * public exponent, private exponent).
 *
 * If BN parameter is NULL then there must be one in the RSA key already.
 *
 * @param [in,out]  rsa  RSA key.
 * @param [in]      n    BN that is the modulus. May be NULL.
 * @param [in]      e    BN that is the public exponent. May be NULL.
 * @param [in]      d    BN that is the private exponent. May be NULL.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_set0_key(WOLFSSL_RSA *rsa, WOLFSSL_BIGNUM *n, WOLFSSL_BIGNUM *e,
     WOLFSSL_BIGNUM *d)
{
    int ret = 1;

    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((rsa == NULL) || ((rsa->n == NULL) && (n == NULL)) ||
            ((rsa->e == NULL) && (e == NULL))) {
        ret = 0;
    }
    if (ret == 1) {
        /* Replace the BNs. */
        if (n != NULL) {
            wolfSSL_BN_free(rsa->n);
            rsa->n = n;
        }
        if (e != NULL) {
            wolfSSL_BN_free(rsa->e);
            rsa->e = e;
        }
        if (d != NULL) {
            /* Private key is sensitive data. */
            wolfSSL_BN_clear_free(rsa->d);
            rsa->d = d;
        }

        /* Set the values into the wolfCrypt RSA key. */
        if (SetRsaInternal(rsa) != 1) {
            if (n != NULL) {
                rsa->n = NULL;
            }
            if (e != NULL) {
                rsa->e = NULL;
            }
            if (d != NULL) {
                rsa->d = NULL;
            }
            ret = 0;
        }
    }

    return ret;
}

/* Get the flags of the RSA key.
 *
 * @param [in] rsa  RSA key.
 * @return  Flags set in RSA key on success.
 * @return  0 when RSA key is NULL.
 */
int wolfSSL_RSA_flags(const WOLFSSL_RSA *rsa)
{
    int ret = 0;

    /* Get flags from the RSA key if available. */
    if (rsa != NULL) {
        ret = rsa->flags;
    }

    return ret;
}

/* Set the flags into the RSA key.
 *
 * @param [in, out] rsa    RSA key.
 * @param [in]      flags  Flags to set.
 */
void wolfSSL_RSA_set_flags(WOLFSSL_RSA *rsa, int flags)
{
    /* Add the flags into RSA key if available. */
    if (rsa != NULL) {
        rsa->flags |= flags;
    }
}

/* Clear the flags in the RSA key.
 *
 * @param [in, out] rsa    RSA key.
 * @param [in]      flags  Flags to clear.
 */
void wolfSSL_RSA_clear_flags(WOLFSSL_RSA *rsa, int flags)
{
    /* Clear the flags passed in that are on the RSA key if available. */
    if (rsa != NULL) {
        rsa->flags &= ~flags;
    }
}

/* Test the flags in the RSA key.
 *
 * @param [in] rsa  RSA key.
 * @return  Matching flags of RSA key on success.
 * @return  0 when RSA key is NULL.
 */
int wolfSSL_RSA_test_flags(const WOLFSSL_RSA *rsa, int flags)
{
    /* Return the flags passed in that are set on the RSA key if available. */
    return (rsa != NULL) ?  (rsa->flags & flags) : 0;
}

/* Get the extra data, by index, associated with the RSA key.
 *
 * @param [in] rsa  RSA key.
 * @param [in] idx  Index of extra data.
 * @return  Extra data (anonymous type) on success.
 * @return  NULL on failure.
 */
void* wolfSSL_RSA_get_ex_data(const WOLFSSL_RSA *rsa, int idx)
{
    WOLFSSL_ENTER("wolfSSL_RSA_get_ex_data");

#ifdef HAVE_EX_DATA
    return (rsa == NULL) ? NULL :
        wolfSSL_CRYPTO_get_ex_data(&rsa->ex_data, idx);
#else
    (void)rsa;
    (void)idx;

    return NULL;
#endif
}

/* Set extra data against the RSA key at an index.
 *
 * @param [in, out] rsa   RSA key.
 * @param [in]      idx   Index set set extra data at.
 * @param [in]      data  Extra data of anonymous type.
 * @return 1 on success.
 * @return 0 on failure.
 */
int wolfSSL_RSA_set_ex_data(WOLFSSL_RSA *rsa, int idx, void *data)
{
    WOLFSSL_ENTER("wolfSSL_RSA_set_ex_data");

#ifdef HAVE_EX_DATA
    return (rsa == NULL) ? 0 :
        wolfSSL_CRYPTO_set_ex_data(&rsa->ex_data, idx, data);
#else
    (void)rsa;
    (void)idx;
    (void)data;

    return 0;
#endif
}

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
/* Set the extra data and cleanup callback against the RSA key at an index.
 *
 * Not OpenSSL API.
 *
 * @param [in, out] rsa     RSA key.
 * @param [in]      idx     Index set set extra data at.
 * @param [in]      data    Extra data of anonymous type.
 * @param [in]      freeCb  Callback function to free extra data.
 * @return 1 on success.
 * @return 0 on failure.
 */
int wolfSSL_RSA_set_ex_data_with_cleanup(WOLFSSL_RSA *rsa, int idx, void *data,
    wolfSSL_ex_data_cleanup_routine_t freeCb)
{
    WOLFSSL_ENTER("wolfSSL_RSA_set_ex_data_with_cleanup");

    return (rsa == NULL) ? 0 :
        wolfSSL_CRYPTO_set_ex_data_with_cleanup(&rsa->ex_data, idx, data,
            freeCb);
}
#endif /* HAVE_EX_DATA_CLEANUP_HOOKS */

/*
 * RSA check key APIs
 */

#ifdef WOLFSSL_RSA_KEY_CHECK
/* Check that the RSA key is valid using wolfCrypt.
 *
 * @param [in] rsa  RSA key.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_check_key(const WOLFSSL_RSA* rsa)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_RSA_check_key");

    /* Validate parameters. */
    if ((rsa == NULL) || (rsa->internal == NULL)) {
        ret = 0;
    }

    /* Constant RSA - assume internal data has been set. */

    /* Check wolfCrypt RSA key. */
    if ((ret == 1) && (wc_CheckRsaKey((RsaKey*)rsa->internal) != 0)) {
        ret = 0;
    }

    WOLFSSL_LEAVE("wolfSSL_RSA_check_key", ret);

    return ret;
}
#endif /* WOLFSSL_RSA_KEY_CHECK */

/*
 * RSA generate APIs
 */

/* Get a random number generator associated with the RSA key.
 *
 * If not able, then get the global if possible.
 * *tmpRng must not be an initialized RNG.
 * *tmpRng is allocated when WOLFSSL_SMALL_STACK is defined and an RNG isn't
 * associated with the wolfCrypt RSA key.
 *
 * @param [in]  rsa         RSA key.
 * @param [out] tmpRng      Temporary random number generator.
 * @param [out] initTmpRng  Temporary random number generator was initialized.
 *
 * @return  A wolfCrypt RNG to use on success.
 * @return  NULL on error.
 */
WC_RNG* WOLFSSL_RSA_GetRNG(WOLFSSL_RSA* rsa, WC_RNG** tmpRng, int* initTmpRng)
{
    WC_RNG* rng = NULL;
    int err = 0;

    /* Check validity of parameters. */
    if ((rsa == NULL) || (initTmpRng == NULL)) {
        err = 1;
    }
    if (!err) {
        /* Haven't initialized any RNG passed through tmpRng. */
        *initTmpRng = 0;

    #if !defined(HAVE_FIPS) && defined(WC_RSA_BLINDING)
        /* Use wolfCrypt RSA key's RNG if available/set. */
        rng = ((RsaKey*)rsa->internal)->rng;
    #endif
    }
    if ((!err) && (rng == NULL) && (tmpRng != NULL)) {
        /* Make an RNG with tmpRng or get global. */
        rng = wolfssl_make_rng(*tmpRng, initTmpRng);
        if ((rng != NULL) && *initTmpRng) {
            *tmpRng = rng;
        }
    }

    return rng;
}

/* Use the wolfCrypt RSA APIs to generate a new RSA key.
 *
 * @param [in, out] rsa   RSA key.
 * @param [in]      bits  Number of bits that the modulus must have.
 * @param [in]      e     A BN object holding the public exponent to use.
 * @param [in]      cb    Status callback. Unused.
 * @return 0 on success.
 * @return wolfSSL native error code on error.
 */
static int wolfssl_rsa_generate_key_native(WOLFSSL_RSA* rsa, int bits,
    WOLFSSL_BIGNUM* e, void* cb)
{
#ifdef WOLFSSL_KEY_GEN
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRng = NULL;
#else
    WC_RNG  _tmpRng[1];
    WC_RNG* tmpRng = _tmpRng;
#endif
    int initTmpRng = 0;
    WC_RNG* rng = NULL;
    long en = 0;
#endif

    (void)cb;

    WOLFSSL_ENTER("wolfssl_rsa_generate_key_native");

#ifdef WOLFSSL_KEY_GEN
    /* Get RNG in wolfCrypt RSA key or initialize a new one (or global). */
    rng = WOLFSSL_RSA_GetRNG(rsa, (WC_RNG**)&tmpRng, &initTmpRng);
    if (rng == NULL) {
        /* Something went wrong so return memory error. */
        ret = MEMORY_E;
    }
    if ((ret == 0) && ((en = (long)wolfSSL_BN_get_word(e)) <= 0)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Generate an RSA key. */
        ret = wc_MakeRsaKey((RsaKey*)rsa->internal, bits, en, rng);
        if (ret != MP_OKAY) {
            WOLFSSL_ERROR_MSG("wc_MakeRsaKey failed");
        }
    }
    if (ret == 0) {
        /* Get the values from wolfCrypt RSA key into external RSA key. */
        ret = SetRsaExternal(rsa);
        if (ret == 1) {
            /* Internal matches external. */
            rsa->inSet = 1;
            /* Return success. */
            ret = 0;
        }
        else {
            /* Something went wrong so return memory error. */
            ret = MEMORY_E;
        }
    }

    /* Finalize RNG if initialized in WOLFSSL_RSA_GetRNG(). */
    if (initTmpRng) {
        wc_FreeRng(tmpRng);
    }
    WC_FREE_VAR_EX(tmpRng, NULL, DYNAMIC_TYPE_RNG);

    return ret;
#else
    WOLFSSL_ERROR_MSG("No Key Gen built in");

    (void)rsa;
    (void)e;
    (void)bits;

    return NOT_COMPILED_IN;
#endif
}

/* Generate an RSA key that has the specified modulus size and public exponent.
 *
 * Note: Because of wc_MakeRsaKey an RSA key size generated can be rounded
 *       down to nearest multiple of 8. For example generating a key of size
 *       2999 bits will make a key of size 374 bytes instead of 375 bytes.
 *
 * @param [in]      bits  Number of bits that the modulus must have i.e. 2048.
 * @param [in]      e     Public exponent to use i.e. 65537.
 * @param [in]      cb    Status callback. Unused.
 * @param [in]      data  Data to pass to status callback. Unused.
 * @return  A new RSA key on success.
 * @return  NULL on failure.
 */
WOLFSSL_RSA* wolfSSL_RSA_generate_key(int bits, unsigned long e,
    void(*cb)(int, int, void*), void* data)
{
    WOLFSSL_RSA*    rsa = NULL;
    WOLFSSL_BIGNUM* bn  = NULL;
    int             err = 0;

    WOLFSSL_ENTER("wolfSSL_RSA_generate_key");

    (void)cb;
    (void)data;

    /* Validate bits. */
    if (bits < 0) {
        WOLFSSL_ERROR_MSG("Bad argument: bits was less than 0");
        err = 1;
    }
    /* Create a new BN to hold public exponent - for when wolfCrypt supports
     * longer values. */
    if ((!err) && ((bn = wolfSSL_BN_new()) == NULL)) {
        WOLFSSL_ERROR_MSG("Error creating big number");
        err = 1;
    }
    /* Set public exponent. */
    if ((!err) && (wolfSSL_BN_set_word(bn, e) != 1)) {
        WOLFSSL_ERROR_MSG("Error using e value");
        err = 1;
    }

    /* Create an RSA key object to hold generated key. */
    if ((!err) && ((rsa = wolfSSL_RSA_new()) == NULL)) {
        WOLFSSL_ERROR_MSG("memory error");
        err = 1;
    }
    while (!err) {
        int ret;

        /* Use wolfCrypt to generate RSA key. */
        ret = wolfssl_rsa_generate_key_native(rsa, bits, bn, NULL);
    #ifdef HAVE_FIPS
        /* Keep trying if failed to find a prime. */
        if (ret == WC_NO_ERR_TRACE(PRIME_GEN_E)) {
            continue;
        }
    #endif
        if (ret != WOLFSSL_ERROR_NONE) {
            /* Unrecoverable error in generation. */
            err = 1;
        }
        /* Done generating - unrecoverable error or success. */
        break;
    }
    if (err) {
        /* Dispose of RSA key object if generation didn't work. */
        wolfSSL_RSA_free(rsa);
        /* Returning NULL on error. */
        rsa = NULL;
    }
    /* Dispose of the temporary BN used for the public exponent. */
    wolfSSL_BN_free(bn);

    return rsa;
}

/* Generate an RSA key that has the specified modulus size and public exponent.
 *
 * Note: Because of wc_MakeRsaKey an RSA key size generated can be rounded
 *       down to nearest multiple of 8. For example generating a key of size
 *       2999 bits will make a key of size 374 bytes instead of 375 bytes.
 *
 * @param [in]      bits  Number of bits that the modulus must have i.e. 2048.
 * @param [in]      e     Public exponent to use, i.e. 65537, as a BN.
 * @param [in]      cb    Status callback. Unused.
 * @return 1 on success.
 * @return 0 on failure.
 */
int wolfSSL_RSA_generate_key_ex(WOLFSSL_RSA* rsa, int bits, WOLFSSL_BIGNUM* e,
    void* cb)
{
    int ret = 1;

    /* Validate parameters. */
    if ((rsa == NULL) || (rsa->internal == NULL)) {
        WOLFSSL_ERROR_MSG("bad arguments");
        ret = 0;
    }
    else {
        for (;;) {
            /* Use wolfCrypt to generate RSA key. */
            int gen_ret = wolfssl_rsa_generate_key_native(rsa, bits, e, cb);
        #ifdef HAVE_FIPS
            /* Keep trying again if public key value didn't work. */
            if (gen_ret == WC_NO_ERR_TRACE(PRIME_GEN_E)) {
                continue;
            }
        #endif
            if (gen_ret != WOLFSSL_ERROR_NONE) {
                /* Unrecoverable error in generation. */
                ret = 0;
            }
            /* Done generating - unrecoverable error or success. */
            break;
        }
    }

    return ret;
}

#endif /* OPENSSL_EXTRA */

/*
 * RSA padding APIs
 */

#ifdef WC_RSA_PSS

#if defined(OPENSSL_EXTRA) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
static int rsa_pss_calc_salt(int saltLen, int hashLen, int emLen)
{
    /* Calculate the salt length to use for special cases. */
    switch (saltLen) {
        /* Negative saltLen values are treated differently. */
        case WC_RSA_PSS_SALTLEN_DIGEST:
            saltLen = hashLen;
            break;
        case WC_RSA_PSS_SALTLEN_MAX_SIGN:
        case WC_RSA_PSS_SALTLEN_MAX:
        #ifdef WOLFSSL_PSS_LONG_SALT
            saltLen = emLen - hashLen - 2;
        #else
            saltLen = hashLen;
            (void)emLen;
        #endif
            break;
        default:
            break;
    }
    if (saltLen < 0) {
        /* log invalid salt, let wolfCrypt handle error */
        WOLFSSL_ERROR_MSG("invalid saltLen");
        saltLen = -3; /* for wolfCrypt to produce error must be < -2 */
    }
    return saltLen;
}
#endif /* OPENSSL_EXTRA && !HAVE_SELFTEST */

#if (defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || \
     defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX)) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))

/* Add PKCS#1 PSS padding to hash.
 *
 *
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
 *
 * @param [in]  rsa      RSA key.
 * @param [out] em       Encoded message.
 * @param [in[  mHash    Message hash.
 * @param [in]  hashAlg  Hash algorithm.
 * @param [in]  mgf1Hash MGF algorithm.
 * @param [in]  saltLen  Length of salt to generate.
 * @return  1 on success.
 * @return  0 on failure.
 */

int wolfSSL_RSA_padding_add_PKCS1_PSS_mgf1(WOLFSSL_RSA *rsa, unsigned char *em,
        const unsigned char *mHash, const WOLFSSL_EVP_MD *hashAlg,
        const WOLFSSL_EVP_MD *mgf1Hash, int saltLen)
{
    int ret = 1;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    int hashLen = 0;
    int emLen = 0;
    int mgf = 0;
    int initTmpRng = 0;
    WC_RNG *rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRng = NULL;
#else
    WC_RNG  _tmpRng[1];
    WC_RNG* tmpRng = _tmpRng;
#endif

    WOLFSSL_ENTER("wolfSSL_RSA_padding_add_PKCS1_PSS");

    /* Validate parameters. */
    if ((rsa == NULL) || (em == NULL) || (mHash == NULL) || (hashAlg == NULL)) {
        ret = 0;
    }

    if (mgf1Hash == NULL)
        mgf1Hash = hashAlg;

    if (ret == 1) {
        /* Get/create an RNG. */
        rng = WOLFSSL_RSA_GetRNG(rsa, (WC_RNG**)&tmpRng, &initTmpRng);
        if (rng == NULL) {
            WOLFSSL_ERROR_MSG("WOLFSSL_RSA_GetRNG error");
            ret = 0;
        }
    }

    /* TODO: use wolfCrypt RSA key to get emLen and bits? */
    /* Set the external data from the wolfCrypt RSA key if not done. */
    if ((ret == 1) && (!rsa->exSet)) {
        ret = SetRsaExternal(rsa);
    }

    if (ret == 1) {
        /* Get the wolfCrypt hash algorithm type. */
        hashType = EvpMd2MacType(hashAlg);
        if (hashType > WC_HASH_TYPE_MAX) {
            WOLFSSL_ERROR_MSG("EvpMd2MacType error");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Get the wolfCrypt MGF algorithm from hash algorithm. */
        mgf = wc_hash2mgf(EvpMd2MacType(mgf1Hash));
        if (mgf == WC_MGF1NONE) {
            WOLFSSL_ERROR_MSG("wc_hash2mgf error");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Get the length of the hash output. */
        hashLen = wolfSSL_EVP_MD_size(hashAlg);
        if (hashLen < 0) {
            WOLFSSL_ERROR_MSG("wolfSSL_EVP_MD_size error");
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Get length of RSA key - encrypted message length. */
        emLen = wolfSSL_RSA_size(rsa);
        if (emLen <= 0) {
            WOLFSSL_ERROR_MSG("wolfSSL_RSA_size error");
            ret = 0;
        }
    }

    if (ret == 1) {
        saltLen = rsa_pss_calc_salt(saltLen, hashLen, emLen);
    }

    if (ret == 1) {
        /* Generate RSA PKCS#1 PSS padding for hash using wolfCrypt. */
        if (wc_RsaPad_ex(mHash, (word32)hashLen, em, (word32)emLen,
                RSA_BLOCK_TYPE_1, rng, WC_RSA_PSS_PAD, hashType, mgf, NULL, 0,
                saltLen, wolfSSL_BN_num_bits(rsa->n), NULL) != MP_OKAY) {
            WOLFSSL_ERROR_MSG("wc_RsaPad_ex error");
            ret = 0;
        }
    }

    /* Finalize RNG if initialized in WOLFSSL_RSA_GetRNG(). */
    if (initTmpRng) {
        wc_FreeRng(tmpRng);
    }
    WC_FREE_VAR_EX(tmpRng, NULL, DYNAMIC_TYPE_RNG);

    return ret;
}

int wolfSSL_RSA_padding_add_PKCS1_PSS(WOLFSSL_RSA *rsa, unsigned char *em,
    const unsigned char *mHash, const WOLFSSL_EVP_MD *hashAlg, int saltLen)
{
    return wolfSSL_RSA_padding_add_PKCS1_PSS_mgf1(rsa, em, mHash, hashAlg, NULL,
            saltLen);
}

/* Checks that the hash is valid for the RSA PKCS#1 PSS encoded message.
 *
 * Refer to wolfSSL_RSA_padding_add_PKCS1_PSS for a diagram.
 *
 * @param [in]  rsa      RSA key.
 * @param [in[  mHash    Message hash.
 * @param [in]  hashAlg  Hash algorithm.
 * @param [in]  mgf1Hash MGF algorithm.
 * @param [in]  em       Encoded message.
 * @param [in]  saltLen  Length of salt to generate.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_verify_PKCS1_PSS_mgf1(WOLFSSL_RSA *rsa,
        const unsigned char *mHash, const WOLFSSL_EVP_MD *hashAlg,
        const WOLFSSL_EVP_MD *mgf1Hash, const unsigned char *em, int saltLen)
{
    int ret = 1;
    int hashLen = 0;
    int mgf = 0;
    int emLen = 0;
    int mPrimeLen = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    byte *mPrime = NULL;
    byte *buf = NULL;

    WOLFSSL_ENTER("wolfSSL_RSA_verify_PKCS1_PSS");

    /* Validate parameters. */
    if ((rsa == NULL) || (mHash == NULL) || (hashAlg == NULL) || (em == NULL)) {
        ret = 0;
    }

    if (mgf1Hash == NULL)
        mgf1Hash = hashAlg;

    /* TODO: use wolfCrypt RSA key to get emLen and bits? */
    /* Set the external data from the wolfCrypt RSA key if not done. */
    if ((ret == 1) && (!rsa->exSet)) {
        ret = SetRsaExternal(rsa);
    }

    if (ret == 1) {
        /* Get hash length for hash algorithm. */
        hashLen = wolfSSL_EVP_MD_size(hashAlg);
        if (hashLen < 0) {
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Get length of RSA key - encrypted message length. */
        emLen = wolfSSL_RSA_size(rsa);
        if (emLen <= 0) {
            WOLFSSL_ERROR_MSG("wolfSSL_RSA_size error");
            ret = 0;
        }
    }

    if (ret == 1) {
        saltLen = rsa_pss_calc_salt(saltLen, hashLen, emLen);
    }

    if (ret == 1) {
        /* Get the wolfCrypt hash algorithm type. */
        hashType = EvpMd2MacType(hashAlg);
        if (hashType > WC_HASH_TYPE_MAX) {
            WOLFSSL_ERROR_MSG("EvpMd2MacType error");
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Get the wolfCrypt MGF algorithm from hash algorithm. */
        if ((mgf = wc_hash2mgf(EvpMd2MacType(mgf1Hash))) == WC_MGF1NONE) {
            WOLFSSL_ERROR_MSG("wc_hash2mgf error");
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Allocate buffer to unpad inline with. */
        buf = (byte*)XMALLOC((size_t)emLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (buf == NULL) {
            WOLFSSL_ERROR_MSG("malloc error");
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Copy encrypted message to temp for inline unpadding. */
        XMEMCPY(buf, em, (size_t)emLen);

        /* Remove and verify the PSS padding. */
        mPrimeLen = wc_RsaUnPad_ex(buf, (word32)emLen, &mPrime,
            RSA_BLOCK_TYPE_1, WC_RSA_PSS_PAD, hashType, mgf, NULL, 0, saltLen,
            wolfSSL_BN_num_bits(rsa->n), NULL);
        if (mPrimeLen < 0) {
            WOLFSSL_ERROR_MSG("wc_RsaPad_ex error");
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Verify the hash is correct. */
        if (wc_RsaPSS_CheckPadding_ex(mHash, (word32)hashLen, mPrime,
                (word32)mPrimeLen, hashType, saltLen,
                wolfSSL_BN_num_bits(rsa->n)) != MP_OKAY) {
            WOLFSSL_ERROR_MSG("wc_RsaPSS_CheckPadding_ex error");
            ret = 0;
        }
    }

    /* Dispose of any allocated buffer. */
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

int wolfSSL_RSA_verify_PKCS1_PSS(WOLFSSL_RSA *rsa, const unsigned char *mHash,
                                 const WOLFSSL_EVP_MD *hashAlg,
                                 const unsigned char *em, int saltLen)
{
    return wolfSSL_RSA_verify_PKCS1_PSS_mgf1(rsa, mHash, hashAlg, NULL, em,
            saltLen);
}
#endif /* (!HAVE_FIPS || FIPS_VERSION_GT(2,0)) && \
          (OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_NGINX) */
#endif /* WC_RSA_PSS */

/*
 * RSA sign/verify APIs
 */

#if defined(WC_RSA_PSS) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,1))
    #ifndef WOLFSSL_PSS_SALT_LEN_DISCOVER
        #define DEF_PSS_SALT_LEN    RSA_PSS_SALT_LEN_DEFAULT
    #else
        #define DEF_PSS_SALT_LEN    RSA_PSS_SALT_LEN_DISCOVER
    #endif
#else
    #define DEF_PSS_SALT_LEN 0 /* not used */
#endif

#if defined(OPENSSL_EXTRA)

/* Encode the message hash.
 *
 * Used by signing and verification.
 *
 * @param [in]  hashAlg   Hash algorithm OID.
 * @param [in]  hash      Hash of message to encode for signing.
 * @param [in]  hLen      Length of hash of message.
 * @param [out] enc       Encoded message hash.
 * @param [out] encLen    Length of encoded message hash.
 * @param [in]  padding   Which padding scheme is being used.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wolfssl_rsa_sig_encode(int hashAlg, const unsigned char* hash,
    unsigned int hLen, unsigned char* enc, unsigned int* encLen, int padding)
{
    int ret = 1;
    int hType = WC_HASH_TYPE_NONE;

    /* Validate parameters. */
    if ((hash == NULL) || (enc == NULL) || (encLen == NULL)) {
        ret = 0;
    }

    if ((ret == 1) && (hashAlg != WC_NID_undef) &&
            (padding == WC_RSA_PKCS1_PADDING)) {
        /* Convert hash algorithm to hash type for PKCS#1.5 padding. */
        hType = (int)nid2oid(hashAlg, oidHashType);
        if (hType == -1) {
            ret = 0;
        }
    }
    if ((ret == 1) && (padding == WC_RSA_PKCS1_PADDING)) {
        /* PKCS#1.5 encoding. */
        word32 encSz = wc_EncodeSignature(enc, hash, hLen, hType);
        if (encSz == 0) {
            WOLFSSL_ERROR_MSG("Bad Encode Signature");
            ret = 0;
        }
        else  {
            *encLen = (unsigned int)encSz;
        }
    }
    /* Other padding schemes require the hash as is. */
    if ((ret == 1) && (padding != WC_RSA_PKCS1_PADDING)) {
        XMEMCPY(enc, hash, hLen);
        *encLen = hLen;
    }

    return ret;
}

/* Sign the message hash using hash algorithm and RSA key.
 *
 * @param [in]  hashAlg   Hash algorithm OID.
 * @param [in]  hash      Hash of message to encode for signing.
 * @param [in]  hLen      Length of hash of message.
 * @param [out] enc       Encoded message hash.
 * @param [out] encLen    Length of encoded message hash.
 * @param [in]  rsa       RSA key.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_sign(int hashAlg, const unsigned char* hash, unsigned int hLen,
    unsigned char* sigRet, unsigned int* sigLen, WOLFSSL_RSA* rsa)
{
    if (sigLen != NULL) {
        /* No size checking in this API */
        *sigLen = RSA_MAX_SIZE / CHAR_BIT;
    }
    /* flag is 1: output complete signature. */
    return wolfSSL_RSA_sign_generic_padding(hashAlg, hash, hLen, sigRet,
        sigLen, rsa, 1, WC_RSA_PKCS1_PADDING);
}

/* Sign the message hash using hash algorithm and RSA key.
 *
 * Not OpenSSL API.
 *
 * @param [in]  hashAlg   Hash algorithm NID.
 * @param [in]  hash      Hash of message to encode for signing.
 * @param [in]  hLen      Length of hash of message.
 * @param [out] enc       Encoded message hash.
 * @param [out] encLen    Length of encoded message hash.
 * @param [in]  rsa       RSA key.
 * @param [in]  flag      When 1: Output encrypted signature.
 *                        When 0: Output encoded hash.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_sign_ex(int hashAlg, const unsigned char* hash,
    unsigned int hLen, unsigned char* sigRet, unsigned int* sigLen,
    WOLFSSL_RSA* rsa, int flag)
{
    int ret = 0;

    if ((flag == 0) || (flag == 1)) {
        if (sigLen != NULL) {
            /* No size checking in this API */
            *sigLen = RSA_MAX_SIZE / CHAR_BIT;
        }
        ret = wolfSSL_RSA_sign_generic_padding(hashAlg, hash, hLen, sigRet,
            sigLen, rsa, flag, WC_RSA_PKCS1_PADDING);
    }

    return ret;
}

int wolfSSL_RSA_sign_generic_padding(int hashAlg, const unsigned char* hash,
    unsigned int hLen, unsigned char* sigRet, unsigned int* sigLen,
    WOLFSSL_RSA* rsa, int flag, int padding)
{
    return wolfSSL_RSA_sign_mgf(hashAlg, hash, hLen, sigRet, sigLen, rsa, flag,
        padding, hashAlg, DEF_PSS_SALT_LEN);
}

/**
 * Sign a message hash with the chosen message digest, padding, and RSA key.
 *
 * Not OpenSSL API.
 *
 * @param [in]      hashAlg  Hash NID
 * @param [in]      hash     Message hash to sign.
 * @param [in]      mLen     Length of message hash to sign.
 * @param [out]     sigRet   Output buffer.
 * @param [in, out] sigLen   On Input: length of sigRet buffer.
 *                           On Output: length of data written to sigRet.
 * @param [in]      rsa      RSA key used to sign the input.
 * @param [in]      flag     1: Output the signature.
 *                           0: Output the value that the unpadded signature
 *                              should be compared to.
 * @param [in]      padding  Padding to use. Only RSA_PKCS1_PSS_PADDING and
 *                           WC_RSA_PKCS1_PADDING are currently supported for
 *                           signing.
 * @param [in]      mgf1Hash MGF1 Hash NID
 * @param [in]      saltLen  Length of RSA PSS salt
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_sign_mgf(int hashAlg, const unsigned char* hash,
    unsigned int hLen, unsigned char* sigRet, unsigned int* sigLen,
    WOLFSSL_RSA* rsa, int flag, int padding, int mgf1Hash, int saltLen)
{
    int     ret        = 1;
    word32  outLen     = 0;
    int     signSz     = 0;
    WC_RNG* rng        = NULL;
    int     initTmpRng = 0;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRng     = NULL;
    byte*   encodedSig = NULL;
#else
    WC_RNG  _tmpRng[1];
    WC_RNG* tmpRng = _tmpRng;
    byte    encodedSig[MAX_ENCODED_SIG_SZ];
#endif
    unsigned int encSz = 0;

    WOLFSSL_ENTER("wolfSSL_RSA_sign_mgf");

    if (flag == 0) {
        /* Only encode message. */
        return wolfssl_rsa_sig_encode(hashAlg, hash, hLen, sigRet, sigLen,
            padding);
    }

    /* Validate parameters. */
    if ((hash == NULL) || (sigRet == NULL) || sigLen == NULL || rsa == NULL) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = 0;
    }

    /* Set wolfCrypt RSA key data from external if not already done. */
    if ((ret == 1) && (!rsa->inSet) && (SetRsaInternal(rsa) != 1)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Get the maximum signature length. */
        outLen = (word32)wolfSSL_BN_num_bytes(rsa->n);
        /* Check not an error return. */
        if (outLen == 0) {
            WOLFSSL_ERROR_MSG("Bad RSA size");
            ret = 0;
        }
        /* Check signature buffer is big enough. */
        else if (outLen > *sigLen) {
            WOLFSSL_ERROR_MSG("Output buffer too small");
            ret = 0;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 1) {
        /* Allocate encoded signature buffer if doing PKCS#1 padding. */
        encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, NULL,
            DYNAMIC_TYPE_SIGNATURE);
        if (encodedSig == NULL) {
            ret = 0;
        }
    }
#endif

    if (ret == 1) {
        /* Get/create an RNG. */
        rng = WOLFSSL_RSA_GetRNG(rsa, (WC_RNG**)&tmpRng, &initTmpRng);
        if (rng == NULL) {
            WOLFSSL_ERROR_MSG("WOLFSSL_RSA_GetRNG error");
            ret = 0;
        }
    }

    /* Either encodes with PKCS#1.5 or copies hash into encodedSig. */
    if ((ret == 1) && (wolfssl_rsa_sig_encode(hashAlg, hash, hLen, encodedSig,
            &encSz, padding) == 0)) {
        WOLFSSL_ERROR_MSG("Bad Encode Signature");
        ret = 0;
    }

    if (ret == 1) {
        switch (padding) {
    #if defined(WC_RSA_NO_PADDING) || defined(WC_RSA_DIRECT)
        case WC_RSA_NO_PAD:
            if ((signSz = wc_RsaDirect(encodedSig, encSz, sigRet, &outLen,
                (RsaKey*)rsa->internal, RSA_PRIVATE_ENCRYPT, rng)) <= 0) {
                WOLFSSL_ERROR_MSG("Bad RSA Sign no pad");
                ret = 0;
            }
            break;
    #endif
    #if defined(WC_RSA_PSS) && !defined(HAVE_SELFTEST) && \
        (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,1))
        case WC_RSA_PKCS1_PSS_PADDING:
        {
            RsaKey* key = (RsaKey*)rsa->internal;
            enum wc_HashType mgf1, hType;
            hType = wc_OidGetHash((int)nid2oid(hashAlg, oidHashType));
            if (mgf1Hash == WC_NID_undef)
                mgf1Hash = hashAlg;
            mgf1 = wc_OidGetHash((int)nid2oid(mgf1Hash, oidHashType));
            /* handle compat layer salt special cases */
            saltLen = rsa_pss_calc_salt(saltLen, wc_HashGetDigestSize(hType),
                wolfSSL_RSA_size(rsa));

            /* Create RSA PSS signature. */
            if ((signSz = wc_RsaPSS_Sign_ex(encodedSig, encSz, sigRet, outLen,
                hType, wc_hash2mgf(mgf1), saltLen, key, rng)) <= 0) {
                WOLFSSL_ERROR_MSG("Bad RSA PSS Sign");
                ret = 0;
            }
            break;
        }
    #endif
    #ifndef WC_NO_RSA_OAEP
        case WC_RSA_PKCS1_OAEP_PADDING:
            /* Not a signature padding scheme. */
            WOLFSSL_ERROR_MSG("RSA_PKCS1_OAEP_PADDING not supported for "
                              "signing");
            ret = 0;
            break;
    #endif
        case WC_RSA_PKCS1_PADDING:
        {
            /* Sign (private encrypt) PKCS#1 encoded signature. */
            if ((signSz = wc_RsaSSL_Sign(encodedSig, encSz, sigRet, outLen,
                    (RsaKey*)rsa->internal, rng)) <= 0) {
                WOLFSSL_ERROR_MSG("Bad PKCS1 RSA Sign");
                ret = 0;
            }
            break;
        }
        default:
            WOLFSSL_ERROR_MSG("Unsupported padding");
            (void)mgf1Hash;
            (void)saltLen;
            ret = 0;
            break;
        }
    }

    if (ret == 1) {
        /* Return the size of signature generated. */
        *sigLen = (unsigned int)signSz;
    }

    /* Finalize RNG if initialized in WOLFSSL_RSA_GetRNG(). */
    if (initTmpRng) {
        wc_FreeRng(tmpRng);
    }
    WC_FREE_VAR_EX(tmpRng, NULL, DYNAMIC_TYPE_RNG);
    WC_FREE_VAR_EX(encodedSig, NULL, DYNAMIC_TYPE_SIGNATURE);

    WOLFSSL_LEAVE("wolfSSL_RSA_sign_mgf", ret);
    return ret;
}

/**
 * Verify a message hash with the chosen message digest, padding, and RSA key.
 *
 * @param [in]  hashAlg  Hash NID
 * @param [in]  hash     Message hash.
 * @param [in]  mLen     Length of message hash.
 * @param [in]  sigRet   Signature data.
 * @param [in]  sigLen   Length of signature data.
 * @param [in]  rsa      RSA key used to sign the input
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_verify(int hashAlg, const unsigned char* hash,
    unsigned int hLen, const unsigned char* sig, unsigned int sigLen,
    WOLFSSL_RSA* rsa)
{
    return wolfSSL_RSA_verify_ex(hashAlg, hash, hLen, sig, sigLen, rsa,
        WC_RSA_PKCS1_PADDING);
}

int wolfSSL_RSA_verify_ex(int hashAlg, const unsigned char* hash,
    unsigned int hLen, const unsigned char* sig, unsigned int sigLen,
    WOLFSSL_RSA* rsa, int padding)
{
    return wolfSSL_RSA_verify_mgf(hashAlg, hash, hLen, sig, sigLen, rsa,
        padding, hashAlg, DEF_PSS_SALT_LEN);
}

/**
 * Verify a message hash with the chosen message digest, padding, and RSA key.
 *
 * Not OpenSSL API.
 *
 * @param [in]  hashAlg  Hash NID
 * @param [in]  hash     Message hash.
 * @param [in]  mLen     Length of message hash.
 * @param [in]  sigRet   Signature data.
 * @param [in]  sigLen   Length of signature data.
 * @param [in]  rsa      RSA key used to sign the input
 * @param [in]  padding  Padding to use. Only RSA_PKCS1_PSS_PADDING and
 *                       WC_RSA_PKCS1_PADDING are currently supported for
 *                       signing.
 * @param [in]  mgf1Hash MGF1 Hash NID
 * @param [in]  saltLen  Length of RSA PSS salt
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_RSA_verify_mgf(int hashAlg, const unsigned char* hash,
    unsigned int hLen, const unsigned char* sig, unsigned int sigLen,
    WOLFSSL_RSA* rsa, int padding, int mgf1Hash, int saltLen)
{
    int              ret    = 1;
#ifdef WOLFSSL_SMALL_STACK
    unsigned char*   encodedSig = NULL;
#else
    unsigned char    encodedSig[MAX_ENCODED_SIG_SZ];
#endif
    unsigned char*   sigDec = NULL;
    unsigned int     len    = MAX_ENCODED_SIG_SZ;
    int              verLen = 0;
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 1)) && !defined(HAVE_SELFTEST)
    enum wc_HashType hType = WC_HASH_TYPE_NONE;
#endif

    WOLFSSL_ENTER("wolfSSL_RSA_verify_mgf");

    /* Validate parameters. */
    if ((hash == NULL) || (sig == NULL) || (rsa == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate memory for decrypted signature. */
        sigDec = (unsigned char *)XMALLOC(sigLen, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (sigDec == NULL) {
            WOLFSSL_ERROR_MSG("Memory allocation failure");
            ret = 0;
        }
    }
    if (ret == 1 && padding == WC_RSA_PKCS1_PSS_PADDING) {
        #if defined(WC_RSA_PSS) && !defined(HAVE_SELFTEST) && \
        (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,1))
        RsaKey* key = (RsaKey*)rsa->internal;
        enum wc_HashType mgf1;
        hType = wc_OidGetHash((int)nid2oid(hashAlg, oidHashType));
        if (mgf1Hash == WC_NID_undef)
            mgf1Hash = hashAlg;
        mgf1 = wc_OidGetHash((int)nid2oid(mgf1Hash, oidHashType));

        /* handle compat layer salt special cases */
        saltLen = rsa_pss_calc_salt(saltLen, wc_HashGetDigestSize(hType),
            wolfSSL_RSA_size(rsa));

        verLen = wc_RsaPSS_Verify_ex((byte*)sig, sigLen, sigDec, sigLen,
            hType, wc_hash2mgf(mgf1), saltLen, key);
        if (verLen > 0) {
            /* Check PSS padding is valid. */
            if (wc_RsaPSS_CheckPadding_ex(hash, hLen, sigDec, (word32)verLen,
                hType, saltLen, mp_count_bits(&key->n)) != 0) {
                WOLFSSL_ERROR_MSG("wc_RsaPSS_CheckPadding_ex error");
                ret = WOLFSSL_FAILURE;
            }
            else {
                /* Success! Free resources and return early */
                XFREE(sigDec, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                return WOLFSSL_SUCCESS;
            }
        }
        else {
            WOLFSSL_ERROR_MSG("wc_RsaPSS_Verify_ex failed!");
            ret = WOLFSSL_FAILURE;
        }
    #else
        (void)mgf1Hash;
        (void)saltLen;
        WOLFSSL_ERROR_MSG("RSA PSS not compiled in!");
        ret = WOLFSSL_FAILURE;
    #endif
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 1) {
        /* Allocate memory for encoded signature. */
        encodedSig = (unsigned char *)XMALLOC(len, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (encodedSig == NULL) {
            WOLFSSL_ERROR_MSG("Memory allocation failure");
            ret = 0;
        }
    }
#endif
    if (ret == 1) {
        /* Make encoded signature to compare with decrypted signature. */
        if (wolfssl_rsa_sig_encode(hashAlg, hash, hLen, encodedSig, &len,
                padding) <= 0) {
            WOLFSSL_ERROR_MSG("Message Digest Error");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Decrypt signature */
    #if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5, 1)) && \
        !defined(HAVE_SELFTEST)
        hType = wc_OidGetHash((int)nid2oid(hashAlg, oidHashType));
        if ((verLen = wc_RsaSSL_Verify_ex2(sig, sigLen, (unsigned char *)sigDec,
                sigLen, (RsaKey*)rsa->internal, padding, hType)) <= 0) {
            WOLFSSL_ERROR_MSG("RSA Decrypt error");
            ret = 0;
        }
    #else
        verLen = wc_RsaSSL_Verify(sig, sigLen, (unsigned char *)sigDec, sigLen,
            (RsaKey*)rsa->internal);
        if (verLen < 0) {
            ret = 0;
        }
    #endif
    }
    if (ret == 1) {
        /* Compare decrypted signature to encoded signature. */
        if (((int)len != verLen) ||
                (XMEMCMP(encodedSig, sigDec, (size_t)verLen) != 0)) {
            WOLFSSL_ERROR_MSG("wolfSSL_RSA_verify_ex failed");
            ret = 0;
        }
    }

    /* Dispose of any allocated data. */
    WC_FREE_VAR_EX(encodedSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sigDec, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    WOLFSSL_LEAVE("wolfSSL_RSA_verify_mgf", ret);
    return ret;
}

/*
 * RSA public/private encrypt/decrypt APIs
 */

/* Encrypt with the RSA public key.
 *
 * Return compliant with OpenSSL.
 *
 * @param [in]  len      Length of data to encrypt.
 * @param [in]  from     Data to encrypt.
 * @param [out] to       Encrypted data.
 * @param [in]  rsa      RSA key.
 * @param [in]  padding  Type of padding to place around plaintext.
 * @return  Size of encrypted data on success.
 * @return  -1 on failure.
 */
int wolfSSL_RSA_public_encrypt(int len, const unsigned char* from,
    unsigned char* to, WOLFSSL_RSA* rsa, int padding)
{
    int ret = 0;
    int initTmpRng = 0;
    WC_RNG *rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRng = NULL;
#else
    WC_RNG  _tmpRng[1];
    WC_RNG* tmpRng = _tmpRng;
#endif
#if !defined(HAVE_FIPS)
    int  mgf = WC_MGF1NONE;
    enum wc_HashType hash = WC_HASH_TYPE_NONE;
    int pad_type = WC_RSA_NO_PAD;
#endif
    int outLen = 0;

    WOLFSSL_ENTER("wolfSSL_RSA_public_encrypt");

    /* Validate parameters. */
    if ((len < 0) || (rsa == NULL) || (rsa->internal == NULL) ||
            (from == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 0) {
    #if !defined(HAVE_FIPS)
        /* Convert to wolfCrypt padding, hash and MGF. */
        switch (padding) {
        case WC_RSA_PKCS1_PADDING:
            pad_type = WC_RSA_PKCSV15_PAD;
            break;
        case WC_RSA_PKCS1_OAEP_PADDING:
            pad_type = WC_RSA_OAEP_PAD;
            hash = WC_HASH_TYPE_SHA;
            mgf = WC_MGF1SHA1;
            break;
        case WC_RSA_NO_PAD:
            pad_type = WC_RSA_NO_PAD;
            break;
        default:
            WOLFSSL_ERROR_MSG("RSA_public_encrypt doesn't support padding "
                              "scheme");
            ret = WOLFSSL_FATAL_ERROR;
        }
    #else
        /* Check for supported padding schemes in FIPS. */
        /* TODO: Do we support more schemes in later versions of FIPS? */
        if (padding != WC_RSA_PKCS1_PADDING) {
            WOLFSSL_ERROR_MSG("RSA_public_encrypt pad type not supported in "
                              "FIPS");
            ret = WOLFSSL_FATAL_ERROR;
        }
    #endif
    }

    /* Set wolfCrypt RSA key data from external if not already done. */
    if ((ret == 0) && (!rsa->inSet) && (SetRsaInternal(rsa) != 1)) {
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 0) {
        /* Calculate maximum length of encrypted data. */
        outLen = wolfSSL_RSA_size(rsa);
        if (outLen == 0) {
            WOLFSSL_ERROR_MSG("Bad RSA size");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        /* Get an RNG. */
        rng = WOLFSSL_RSA_GetRNG(rsa, (WC_RNG**)&tmpRng, &initTmpRng);
        if (rng == NULL) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        /* Use wolfCrypt to public-encrypt with RSA key. */
    #if !defined(HAVE_FIPS)
        ret = wc_RsaPublicEncrypt_ex(from, (word32)len, to, (word32)outLen,
            (RsaKey*)rsa->internal, rng, pad_type, hash, mgf, NULL, 0);
    #else
        ret = wc_RsaPublicEncrypt(from, (word32)len, to, (word32)outLen,
            (RsaKey*)rsa->internal, rng);
    #endif
    }

    /* Finalize RNG if initialized in WOLFSSL_RSA_GetRNG(). */
    if (initTmpRng) {
        wc_FreeRng(tmpRng);
    }
    WC_FREE_VAR_EX(tmpRng, NULL, DYNAMIC_TYPE_RNG);

    /* wolfCrypt error means return -1. */
    if (ret <= 0) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    WOLFSSL_LEAVE("wolfSSL_RSA_public_encrypt", ret);
    return ret;
}

/* Decrypt with the RSA public key.
 *
 * Return compliant with OpenSSL.
 *
 * @param [in]  len      Length of encrypted data.
 * @param [in]  from     Encrypted data.
 * @param [out] to       Decrypted data.
 * @param [in]  rsa      RSA key.
 * @param [in]  padding  Type of padding to around plaintext to remove.
 * @return  Size of decrypted data on success.
 * @return  -1 on failure.
 */
int wolfSSL_RSA_private_decrypt(int len, const unsigned char* from,
    unsigned char* to, WOLFSSL_RSA* rsa, int padding)
{
    int ret = 0;
#if !defined(HAVE_FIPS)
    int mgf = WC_MGF1NONE;
    enum wc_HashType hash = WC_HASH_TYPE_NONE;
    int pad_type = WC_RSA_NO_PAD;
#endif
    int outLen = 0;

    WOLFSSL_ENTER("wolfSSL_RSA_private_decrypt");

    /* Validate parameters. */
    if ((len < 0) || (rsa == NULL) || (rsa->internal == NULL) ||
            (from == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 0) {
    #if !defined(HAVE_FIPS)
        switch (padding) {
        case WC_RSA_PKCS1_PADDING:
            pad_type = WC_RSA_PKCSV15_PAD;
            break;
        case WC_RSA_PKCS1_OAEP_PADDING:
            pad_type = WC_RSA_OAEP_PAD;
            hash = WC_HASH_TYPE_SHA;
            mgf = WC_MGF1SHA1;
            break;
        case WC_RSA_NO_PAD:
            pad_type = WC_RSA_NO_PAD;
            break;
        default:
            WOLFSSL_ERROR_MSG("RSA_private_decrypt unsupported padding");
            ret = WOLFSSL_FATAL_ERROR;
        }
    #else
        /* Check for supported padding schemes in FIPS. */
        /* TODO: Do we support more schemes in later versions of FIPS? */
        if (padding != WC_RSA_PKCS1_PADDING) {
            WOLFSSL_ERROR_MSG("RSA_public_encrypt pad type not supported in "
                              "FIPS");
            ret = WOLFSSL_FATAL_ERROR;
        }
    #endif
    }

    /* Set wolfCrypt RSA key data from external if not already done. */
    if ((ret == 0) && (!rsa->inSet) && (SetRsaInternal(rsa) != 1)) {
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 0) {
        /* Calculate maximum length of decrypted data. */
        outLen = wolfSSL_RSA_size(rsa);
        if (outLen == 0) {
            WOLFSSL_ERROR_MSG("Bad RSA size");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        /* Use wolfCrypt to private-decrypt with RSA key.
         * Size of 'to' buffer must be size of RSA key */
    #if !defined(HAVE_FIPS)
        ret = wc_RsaPrivateDecrypt_ex(from, (word32)len, to, (word32)outLen,
            (RsaKey*)rsa->internal, pad_type, hash, mgf, NULL, 0);
    #else
        ret = wc_RsaPrivateDecrypt(from, (word32)len, to, (word32)outLen,
            (RsaKey*)rsa->internal);
    #endif
    }

    /* wolfCrypt error means return -1. */
    if (ret <= 0) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    WOLFSSL_LEAVE("wolfSSL_RSA_private_decrypt", ret);
    return ret;
}

/* Decrypt with the RSA public key.
 *
 * @param [in]  len      Length of encrypted data.
 * @param [in]  from     Encrypted data.
 * @param [out] to       Decrypted data.
 * @param [in]  rsa      RSA key.
 * @param [in]  padding  Type of padding to around plaintext to remove.
 * @return  Size of decrypted data on success.
 * @return  -1 on failure.
 */
int wolfSSL_RSA_public_decrypt(int len, const unsigned char* from,
    unsigned char* to, WOLFSSL_RSA* rsa, int padding)
{
    int ret = 0;
#if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
    int pad_type = WC_RSA_NO_PAD;
#endif
    int outLen = 0;

    WOLFSSL_ENTER("wolfSSL_RSA_public_decrypt");

    /* Validate parameters. */
    if ((len < 0) || (rsa == NULL) || (rsa->internal == NULL) ||
            (from == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 0) {
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
        switch (padding) {
        case WC_RSA_PKCS1_PADDING:
            pad_type = WC_RSA_PKCSV15_PAD;
            break;
        case WC_RSA_NO_PAD:
            pad_type = WC_RSA_NO_PAD;
            break;
        /* TODO: RSA_X931_PADDING not supported */
        default:
            WOLFSSL_ERROR_MSG("RSA_public_decrypt unsupported padding");
            ret = WOLFSSL_FATAL_ERROR;
        }
    #else
        if (padding != WC_RSA_PKCS1_PADDING) {
            WOLFSSL_ERROR_MSG("RSA_public_decrypt pad type not supported in "
                              "FIPS");
            ret = WOLFSSL_FATAL_ERROR;
        }
    #endif
    }

    /* Set wolfCrypt RSA key data from external if not already done. */
    if ((ret == 0) && (!rsa->inSet) && (SetRsaInternal(rsa) != 1)) {
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 0) {
        /* Calculate maximum length of encrypted data. */
        outLen = wolfSSL_RSA_size(rsa);
        if (outLen == 0) {
            WOLFSSL_ERROR_MSG("Bad RSA size");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        /* Use wolfCrypt to public-decrypt with RSA key. */
    #if !defined(HAVE_SELFTEST) && (!defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0))
        /* Size of 'to' buffer must be size of RSA key. */
        ret = wc_RsaSSL_Verify_ex(from, (word32)len, to, (word32)outLen,
            (RsaKey*)rsa->internal, pad_type);
    #else
        /* For FIPS v1/v2 only PKCSV15 padding is supported */
        ret = wc_RsaSSL_Verify(from, (word32)len, to, (word32)outLen,
            (RsaKey*)rsa->internal);
    #endif
    }

    /* wolfCrypt error means return -1. */
    if (ret <= 0) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    WOLFSSL_LEAVE("wolfSSL_RSA_public_decrypt", ret);
    return ret;
}

/* Encrypt with the RSA private key.
 *
 * Calls wc_RsaSSL_Sign.
 *
 * @param [in]  len      Length of data to encrypt.
 * @param [in]  from     Data to encrypt.
 * @param [out] to       Encrypted data.
 * @param [in]  rsa      RSA key.
 * @param [in]  padding  Type of padding to place around plaintext.
 * @return  Size of encrypted data on success.
 * @return  -1 on failure.
 */
int wolfSSL_RSA_private_encrypt(int len, const unsigned char* from,
    unsigned char* to, WOLFSSL_RSA* rsa, int padding)
{
    int ret = 0;
    int initTmpRng = 0;
    WC_RNG *rng = NULL;
#ifdef WOLFSSL_SMALL_STACK
    WC_RNG* tmpRng = NULL;
#else
    WC_RNG  _tmpRng[1];
    WC_RNG* tmpRng = _tmpRng;
#endif

    WOLFSSL_ENTER("wolfSSL_RSA_private_encrypt");

    /* Validate parameters. */
    if ((len < 0) || (rsa == NULL) || (rsa->internal == NULL) ||
            (from == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 0) {
        switch (padding) {
        case WC_RSA_PKCS1_PADDING:
    #ifdef WC_RSA_NO_PADDING
        case WC_RSA_NO_PAD:
    #endif
            break;
        /* TODO: RSA_X931_PADDING not supported */
        default:
            WOLFSSL_ERROR_MSG("RSA_private_encrypt unsupported padding");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    /* Set wolfCrypt RSA key data from external if not already done. */
    if ((ret == 0) && (!rsa->inSet) && (SetRsaInternal(rsa) != 1)) {
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 0) {
        /* Get an RNG. */
        rng = WOLFSSL_RSA_GetRNG(rsa, (WC_RNG**)&tmpRng, &initTmpRng);
        if (rng == NULL) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        /* Use wolfCrypt to private-encrypt with RSA key.
         * Size of output buffer must be size of RSA key. */
        if (padding == WC_RSA_PKCS1_PADDING) {
            ret = wc_RsaSSL_Sign(from, (word32)len, to,
                (word32)wolfSSL_RSA_size(rsa), (RsaKey*)rsa->internal, rng);
        }
    #ifdef WC_RSA_NO_PADDING
        else if (padding == WC_RSA_NO_PAD) {
            word32 outLen = (word32)wolfSSL_RSA_size(rsa);
            ret = wc_RsaFunction(from, (word32)len, to, &outLen,
                    RSA_PRIVATE_ENCRYPT, (RsaKey*)rsa->internal, rng);
            if (ret == 0)
                ret = (int)outLen;
        }
    #endif
    }

    /* Finalize RNG if initialized in WOLFSSL_RSA_GetRNG(). */
    if (initTmpRng) {
        wc_FreeRng(tmpRng);
    }
    WC_FREE_VAR_EX(tmpRng, NULL, DYNAMIC_TYPE_RNG);

    /* wolfCrypt error means return -1. */
    if (ret <= 0) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    WOLFSSL_LEAVE("wolfSSL_RSA_private_encrypt", ret);
    return ret;
}

/*
 * RSA misc operation APIs
 */

/* Calculate d mod p-1 and q-1 into BNs.
 *
 * Not OpenSSL API.
 *
 * @param [in, out] rsa  RSA key.
 * @return 1 on success.
 * @return -1 on failure.
 */
int wolfSSL_RSA_GenAdd(WOLFSSL_RSA* rsa)
{
    int     ret = 1;
    int     err;
    mp_int* t = NULL;
    WC_DECLARE_VAR(tmp, mp_int, 1, 0);

    WOLFSSL_ENTER("wolfSSL_RsaGenAdd");

    /* Validate parameters. */
    if ((rsa == NULL) || (rsa->p == NULL) || (rsa->q == NULL) ||
            (rsa->d == NULL) || (rsa->dmp1 == NULL) || (rsa->dmq1 == NULL)) {
        WOLFSSL_ERROR_MSG("rsa no init error");
        ret = WOLFSSL_FATAL_ERROR;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == 1) {
        tmp = (mp_int *)XMALLOC(sizeof(*tmp), rsa->heap,
                                     DYNAMIC_TYPE_TMP_BUFFER);
        if (tmp == NULL) {
            WOLFSSL_ERROR_MSG("Memory allocation failure");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
#endif

    if (ret == 1) {
        /* Initialize temp MP integer. */
        if (mp_init(tmp) != MP_OKAY) {
            WOLFSSL_ERROR_MSG("mp_init error");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 1) {
        t = tmp;

        /* Sub 1 from p into temp. */
        err = mp_sub_d((mp_int*)rsa->p->internal, 1, tmp);
        if (err != MP_OKAY) {
            WOLFSSL_ERROR_MSG("mp_sub_d error");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 1) {
        /* Calculate d mod (p - 1) into dmp1 MP integer of BN. */
        err = mp_mod((mp_int*)rsa->d->internal, tmp,
            (mp_int*)rsa->dmp1->internal);
        if (err != MP_OKAY) {
            WOLFSSL_ERROR_MSG("mp_mod error");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 1) {
        /* Sub 1 from q into temp. */
        err = mp_sub_d((mp_int*)rsa->q->internal, 1, tmp);
        if (err != MP_OKAY) {
            WOLFSSL_ERROR_MSG("mp_sub_d error");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 1) {
        /* Calculate d mod (q - 1) into dmq1 MP integer of BN. */
        err = mp_mod((mp_int*)rsa->d->internal, tmp,
            (mp_int*)rsa->dmq1->internal);
        if (err != MP_OKAY) {
            WOLFSSL_ERROR_MSG("mp_mod error");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    mp_clear(t);

#ifdef WOLFSSL_SMALL_STACK
    if (rsa != NULL) {
        XFREE(tmp, rsa->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif

    return ret;
}


#ifndef NO_WOLFSSL_STUB
/* Enable blinding for RSA key operations.
 *
 * Blinding is a compile time option in wolfCrypt.
 *
 * @param [in] rsa    RSA key. Unused.
 * @param [in] bnCtx  BN context to use for blinding. Unused.
 * @return 1 always.
 */
int wolfSSL_RSA_blinding_on(WOLFSSL_RSA* rsa, WOLFSSL_BN_CTX* bnCtx)
{
    WOLFSSL_STUB("RSA_blinding_on");
    WOLFSSL_ENTER("wolfSSL_RSA_blinding_on");

    (void)rsa;
    (void)bnCtx;

    return 1;  /* on by default */
}
#endif

#endif /* OPENSSL_EXTRA */

#endif /* !NO_RSA */

/*******************************************************************************
 * END OF RSA API
 ******************************************************************************/

#endif /* !WOLFSSL_PK_RSA_INCLUDED */
