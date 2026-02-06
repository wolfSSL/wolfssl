/* evp_pk.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if !defined(WOLFSSL_EVP_PK_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning evp_pk.c does not need to be compiled separately from ssl.c
    #endif
#elif defined(WOLFCRYPT_ONLY)
#else

/*******************************************************************************
 * START OF d2i APIs
 ******************************************************************************/

#ifndef NO_CERTS

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/**
 * Make an EVP PKEY and put data and type in.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @param [in]      type   The type of public/private key.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2i_make_pkey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    word32 memSz, int priv, int type)
{
    WOLFSSL_EVP_PKEY* pkey;
    int ret = 1;

    /* Get or create the EVP PKEY object. */
    if (*out != NULL) {
        pkey = *out;
    }
    else {
        pkey = wolfSSL_EVP_PKEY_new();
        if (pkey == NULL) {
            WOLFSSL_MSG("wolfSSL_EVP_PKEY_new error");
            return 0;
        }
    }

    /* Set the size and allocate memory for key data to be copied into. */
    pkey->pkey_sz = (int)memSz;
    pkey->pkey.ptr = (char*)XMALLOC((size_t)memSz, NULL,
        priv ? DYNAMIC_TYPE_PRIVATE_KEY : DYNAMIC_TYPE_PUBLIC_KEY);
    if (pkey->pkey.ptr == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        /* Copy in key data, set key type passed in and return object. */
        XMEMCPY(pkey->pkey.ptr, mem, memSz);
        pkey->type = type;
        *out = pkey;
    }
    if ((ret == 0) && (*out == NULL)) {
        /* Dispose of object allocated in this function. */
        wolfSSL_EVP_PKEY_free(pkey);
    }

    return ret;
}

#if !defined(NO_RSA)
/**
 * Try to make an RSA EVP PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2iTryRsaKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_RSA* rsaObj = NULL;
    word32 keyIdx = 0;
    int isRsaKey;
    int ret = 1;
    WC_DECLARE_VAR(rsa, RsaKey, 1, NULL);

    WC_ALLOC_VAR_EX(rsa, RsaKey, 1, NULL, DYNAMIC_TYPE_RSA, return 0);

    XMEMSET(rsa, 0, sizeof(RsaKey));

    if (wc_InitRsaKey(rsa, NULL) != 0) {
        WC_FREE_VAR_EX(rsa, NULL, DYNAMIC_TYPE_RSA);
        return 0;
    }
    /* Try decoding data as an RSA private/public key. */
    if (priv) {
        isRsaKey =
            (wc_RsaPrivateKeyDecode(mem, &keyIdx, rsa, (word32)memSz) == 0);
    }
    else {
        isRsaKey =
            (wc_RsaPublicKeyDecode(mem, &keyIdx, rsa, (word32)memSz) == 0);
    }
    wc_FreeRsaKey(rsa);
    WC_FREE_VAR_EX(rsa, NULL, DYNAMIC_TYPE_RSA);

    if (!isRsaKey) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* Create RSA key object from data. */
    rsaObj = wolfssl_rsa_d2i(NULL, mem, keyIdx,
        priv ? WOLFSSL_RSA_LOAD_PRIVATE : WOLFSSL_RSA_LOAD_PUBLIC);
    if (rsaObj == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        /* Create an EVP PKEY object. */
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_RSA);
    }
    if (ret == 1) {
        /* Put RSA key object into EVP PKEY object. */
        (*out)->ownRsa = 1;
        (*out)->rsa = rsaObj;
    }
    if (ret == 0) {
        wolfSSL_RSA_free(rsaObj);
    }

    return ret;
}
#endif /* !NO_RSA */

#if defined(HAVE_ECC) && defined(OPENSSL_EXTRA)
/**
 * Try to make an ECC EVP PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2iTryEccKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_EC_KEY* ec = NULL;
    word32  keyIdx = 0;
    int     isEccKey;
    int     ret = 1;
    WC_DECLARE_VAR(ecc, ecc_key, 1, NULL);

    WC_ALLOC_VAR_EX(ecc, ecc_key, 1, NULL, DYNAMIC_TYPE_ECC, return 0);

    XMEMSET(ecc, 0, sizeof(ecc_key));

    if (wc_ecc_init(ecc) != 0) {
        WC_FREE_VAR_EX(ecc, NULL, DYNAMIC_TYPE_ECC);
        return 0;
    }

    /* Try decoding data as an ECC private/public key. */
    if (priv) {
        isEccKey =
            (wc_EccPrivateKeyDecode(mem, &keyIdx, ecc, (word32)memSz) == 0);
    }
    else {
        isEccKey =
            (wc_EccPublicKeyDecode(mem, &keyIdx, ecc, (word32)memSz) == 0);
    }
    wc_ecc_free(ecc);
    WC_FREE_VAR_EX(ecc, NULL, DYNAMIC_TYPE_ECC);

    if (!isEccKey) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* Create EC key object from data. */
    ec = wolfSSL_EC_KEY_new();
    if (ec == NULL) {
        ret = 0;
    }
    if ((ret == 1) && (wolfSSL_EC_KEY_LoadDer_ex(ec, mem, keyIdx,
            priv ? WOLFSSL_RSA_LOAD_PRIVATE : WOLFSSL_RSA_LOAD_PUBLIC) != 1)) {
        ret = 0;
    }
    if (ret == 1) {
        /* Create an EVP PKEY object. */
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_EC);
    }
    if (ret == 1) {
        /* Put RSA key object into EVP PKEY object. */
        (*out)->ownEcc = 1;
        (*out)->ecc = ec;
    }
    if (ret == 0) {
        wolfSSL_EC_KEY_free(ec);
    }

    return ret;
}
#endif /* HAVE_ECC && OPENSSL_EXTRA */

#if !defined(NO_DSA)
/**
 * Try to make a DSA EVP PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2iTryDsaKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_DSA* dsaObj;
    word32 keyIdx = 0;
    int     isDsaKey;
    int     ret = 1;
    WC_DECLARE_VAR(dsa, DsaKey, 1, NULL);

    WC_ALLOC_VAR_EX(dsa, DsaKey, 1, NULL, DYNAMIC_TYPE_DSA, return 0);

    XMEMSET(dsa, 0, sizeof(DsaKey));

    if (wc_InitDsaKey(dsa) != 0) {
        WC_FREE_VAR_EX(dsa, NULL, DYNAMIC_TYPE_DSA);
        return 0;
    }

    /* Try decoding data as a DSA private/public key. */
    if (priv) {
        isDsaKey =
            (wc_DsaPrivateKeyDecode(mem, &keyIdx, dsa, (word32)memSz) == 0);
    }
    else {
        isDsaKey =
            (wc_DsaPublicKeyDecode(mem, &keyIdx, dsa, (word32)memSz) == 0);
    }
    wc_FreeDsaKey(dsa);
    WC_FREE_VAR_EX(dsa, NULL, DYNAMIC_TYPE_DSA);

    /* test if DSA key */
    if (!isDsaKey) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* Create DSA key object from data. */
    dsaObj = wolfSSL_DSA_new();
    if (dsaObj == NULL) {
        ret = 0;
    }
    if ((ret == 1) && (wolfSSL_DSA_LoadDer_ex(dsaObj, mem, keyIdx,
            priv ? WOLFSSL_RSA_LOAD_PRIVATE : WOLFSSL_RSA_LOAD_PUBLIC) != 1)) {
        ret = 0;
    }
    if (ret == 1) {
        /* Create an EVP PKEY object. */
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_DSA);
    }
    if (ret == 1) {
        /* Put RSA key object into EVP PKEY object. */
        (*out)->ownDsa = 1;
        (*out)->dsa = dsaObj;
    }
    if (ret == 0) {
        wolfSSL_DSA_free(dsaObj);
    }

    return ret;
}
#endif /* NO_DSA */

#if !defined(NO_DH) && (defined(WOLFSSL_QT) || defined(OPENSSL_ALL))
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION > 2))
/**
 * Try to make a DH EVP PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2iTryDhKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_DH* dhObj;
    int isDhKey;
    word32 keyIdx = 0;
    int ret = 1;
    WC_DECLARE_VAR(dh, DhKey, 1, NULL);

    WC_ALLOC_VAR_EX(dh, DhKey, 1, NULL, DYNAMIC_TYPE_DH, return 0);

    XMEMSET(dh, 0, sizeof(DhKey));

    if (wc_InitDhKey(dh) != 0) {
        WC_FREE_VAR_EX(dh, NULL, DYNAMIC_TYPE_DH);
        return 0;
    }

    /* Try decoding data as a DH public key. */
    isDhKey = (wc_DhKeyDecode(mem, &keyIdx, dh, (word32)memSz) == 0);
    wc_FreeDhKey(dh);
    WC_FREE_VAR_EX(dh, NULL, DYNAMIC_TYPE_DH);

    /* test if DH key */
    if (!isDhKey) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* Create DH key object from data. */
    dhObj = wolfSSL_DH_new();
    if (dhObj == NULL) {
        ret = 0;
    }
    if ((ret == 1) && (wolfSSL_DH_LoadDer(dhObj, mem, keyIdx) != 1)) {
        ret = 0;
    }
    if (ret == 1) {
        /* Create an EVP PKEY object. */
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_DH);
    }
    if (ret == 1) {
        /* Put RSA key object into EVP PKEY object. */
        (*out)->ownDh = 1;
        (*out)->dh = dhObj;
    }
    if (ret == 0) {
        wolfSSL_DH_free(dhObj);
    }

    return ret;
}
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH && (WOLFSSL_QT || OPENSSL_ALL) */

#if !defined(NO_DH) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_DH_EXTRA)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
        (HAVE_FIPS_VERSION > 2))
/**
 * Try to make a DH EVP PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2iTryAltDhKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_DH* dhObj;
    word32  keyIdx = 0;
    DhKey*  key = NULL;
    int elements;
    int ret = 1;

    /* Create DH key object from data. */
    dhObj = wolfSSL_DH_new();
    if (dhObj == NULL) {
        return 0;
    }

    key = (DhKey*)dhObj->internal;
    /* Try decoding data as a DH public key. */
    if (wc_DhKeyDecode(mem, &keyIdx, key, (word32)memSz) != 0) {
        ret = 0;
    }
    if (ret == 1) {
        /* DH key has data and is external to DH object. */
        elements = ELEMENT_P | ELEMENT_G | ELEMENT_Q | ELEMENT_PUB;
        if (priv) {
            elements |= ELEMENT_PRV;
        }
        if (SetDhExternal_ex(dhObj, elements) != WOLFSSL_SUCCESS ) {
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Create an EVP PKEY object. */
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_DH);
    }
    if (ret == 1) {
        /* Put RSA key object into EVP PKEY object. */
        (*out)->ownDh = 1;
        (*out)->dh = dhObj;
    }
    if (ret == 0) {
        wolfSSL_DH_free(dhObj);
    }

    return ret;
}
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH &&  OPENSSL_EXTRA && WOLFSSL_DH_EXTRA */

#ifdef HAVE_FALCON
/**
 * Attempt to import a private Falcon key at a specified level.
 *
 * @param [in] falcon  Falcon key object.
 * @param [in] level   Level of Falcon key.
 * @param [in] mem     Memory containing key data.
 * @param [in] memSz   Size of key data in bytes.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2i_falcon_priv_key_level(falcon_key* falcon, byte level,
    const unsigned char* mem, long memSz)
{
    return (wc_falcon_set_level(falcon, level) == 0) &&
           (wc_falcon_import_private_only(mem, (word32)memSz, falcon) == 0);
}

/**
 * Attempt to import a public Falcon key at a specified level.
 *
 * @param [in] falcon  Falcon key object.
 * @param [in] level   Level of Falcon key.
 * @param [in] mem     Memory containing key data.
 * @param [in] memSz   Size of key data in bytes.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2i_falcon_pub_key_level(falcon_key* falcon, byte level,
    const unsigned char* mem, long memSz)
{
    return (wc_falcon_set_level(falcon, level) == 0) &&
           (wc_falcon_import_public(mem, (word32)memSz, falcon) == 0);
}

/**
 * Try to make a Falcon EVP PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2iTryFalconKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    int isFalcon = 0;
    WC_DECLARE_VAR(falcon, falcon_key, 1, NULL);

    WC_ALLOC_VAR_EX(falcon, falcon_key, 1, NULL, DYNAMIC_TYPE_FALCON,
        return 0);

    if (wc_falcon_init(falcon) != 0) {
        WC_FREE_VAR_EX(falcon, NULL, DYNAMIC_TYPE_FALCON);
        return 0;
    }

    /* Try decoding data as a Falcon private/public key. */
    if (priv) {
        /* Try level 1 */
        isFalcon = d2i_falcon_priv_key_level(falcon, 1, mem, memSz);
        if (!isFalcon) {
            /* Try level 5 */
            isFalcon = d2i_falcon_priv_key_level(falcon, 5, mem, memSz);
        }
    }
    else {
        /* Try level 1 */
        isFalcon = d2i_falcon_pub_key_level(falcon, 1, mem, memSz);
        if (!isFalcon) {
            /* Try level 5 */
            isFalcon = d2i_falcon_pub_key_level(falcon, 5, mem, memSz);
        }
    }
    /* Dispose of any Falcon key created. */
    wc_falcon_free(falcon);
    WC_FREE_VAR_EX(falcon, NULL, DYNAMIC_TYPE_FALCON);

    if (!isFalcon) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* Create an EVP PKEY object. */
    return d2i_make_pkey(out, NULL, 0, priv, WC_EVP_PKEY_FALCON);
}
#endif /* HAVE_FALCON */

#ifdef HAVE_DILITHIUM
/**
 * Attempt to import a private Dilithium key at a specified level.
 *
 * @param [in] dilithium  Dilithium key object.
 * @param [in] level      Level of Dilithium key.
 * @param [in] mem        Memory containing key data.
 * @param [in] memSz      Size of key data in bytes.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2i_dilithium_priv_key_level(dilithium_key* dilithium, byte level,
    const unsigned char* mem, long memSz)
{
    return (wc_dilithium_set_level(dilithium, level) == 0) &&
           (wc_dilithium_import_private(mem, (word32)memSz, dilithium) == 0);
}

/**
 * Attempt to import a public Dilithium key at a specified level.
 *
 * @param [in] dilithium  Dilithium key object.
 * @param [in] level      Level of Dilithium key.
 * @param [in] mem        Memory containing key data.
 * @param [in] memSz      Size of key data in bytes.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2i_dilithium_pub_key_level(dilithium_key* dilithium, byte level,
    const unsigned char* mem, long memSz)
{
    return (wc_dilithium_set_level(dilithium, level) == 0) &&
           (wc_dilithium_import_public(mem, (word32)memSz, dilithium) == 0);
}

/**
 * Try to make a Dilithium EVP PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static int d2iTryDilithiumKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    int isDilithium = 0;
    WC_DECLARE_VAR(dilithium, dilithium_key, 1, NULL);

    WC_ALLOC_VAR_EX(dilithium, dilithium_key, 1, NULL, DYNAMIC_TYPE_DILITHIUM,
        return 0);

    if (wc_dilithium_init(dilithium) != 0) {
        WC_FREE_VAR_EX(dilithium, NULL, DYNAMIC_TYPE_DILITHIUM);
        return 0;
    }

    /* Try decoding data as a Dilithium private/public key. */
    if (priv) {
        isDilithium = d2i_dilithium_priv_key_level(dilithium, WC_ML_DSA_44,
            mem, memSz);
        if (!isDilithium) {
            isDilithium = d2i_dilithium_priv_key_level(dilithium, WC_ML_DSA_65,
                mem, memSz);
        }
        if (!isDilithium) {
            isDilithium = d2i_dilithium_priv_key_level(dilithium, WC_ML_DSA_87,
                mem, memSz);
        }
    }
    else {
        isDilithium = d2i_dilithium_pub_key_level(dilithium, WC_ML_DSA_44,
            mem, memSz);
        if (!isDilithium) {
            isDilithium = d2i_dilithium_pub_key_level(dilithium, WC_ML_DSA_65,
                mem, memSz);
        }
        if (!isDilithium) {
            isDilithium = d2i_dilithium_pub_key_level(dilithium, WC_ML_DSA_87,
                mem, memSz);
        }
    }
    /* Dispose of any Dilithium key created. */
    wc_dilithium_free(dilithium);
    WC_FREE_VAR_EX(dilithium, NULL, DYNAMIC_TYPE_DILITHIUM);

    if (!isDilithium) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* Create an EVP PKEY object. */
    return d2i_make_pkey(out, NULL, 0, priv, WC_EVP_PKEY_DILITHIUM);
}
#endif /* HAVE_DILITHIUM */

/**
 * Try to make a WOLFSSL_EVP_PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @return  1 on success.
 * @return  0 otherwise.
 */
static WOLFSSL_EVP_PKEY* d2i_evp_pkey_try(WOLFSSL_EVP_PKEY** out,
    const unsigned char** in, long inSz, int priv)
{
    WOLFSSL_EVP_PKEY* pkey = NULL;

    WOLFSSL_ENTER("d2i_evp_pkey_try");

    if (in == NULL || *in == NULL || inSz < 0) {
        WOLFSSL_MSG("Bad argument");
        return NULL;
    }

    if ((out != NULL) && (*out != NULL)) {
        pkey = *out;
    }

#if !defined(NO_RSA)
    if (d2iTryRsaKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* NO_RSA */
#if defined(HAVE_ECC) && defined(OPENSSL_EXTRA)
    if (d2iTryEccKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* HAVE_ECC && OPENSSL_EXTRA */
#if !defined(NO_DSA)
    if (d2iTryDsaKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* NO_DSA */
#if !defined(NO_DH) && (defined(WOLFSSL_QT) || defined(OPENSSL_ALL))
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION > 2))
    if (d2iTryDhKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH && (WOLFSSL_QT || OPENSSL_ALL) */

#if !defined(NO_DH) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_DH_EXTRA)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
        (HAVE_FIPS_VERSION > 2))
    if (d2iTryAltDhKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH &&  OPENSSL_EXTRA && WOLFSSL_DH_EXTRA */

#ifdef HAVE_FALCON
    if (d2iTryFalconKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* HAVE_FALCON */
#ifdef HAVE_DILITHIUM
    if (d2iTryDilithiumKey(&pkey, *in, inSz, priv) >= 0) {
        ;
    }
    else
#endif /* HAVE_DILITHIUM */
    {
        WOLFSSL_MSG("d2i_evp_pkey_try couldn't determine key type");
    }

    if ((pkey != NULL) && (out != NULL)) {
        *out = pkey;
    }
    return pkey;
}
#endif /* OPENSSL_EXTRA || WPA_SMALL */

#ifdef OPENSSL_EXTRA
/* Converts a DER encoded public key to a WOLFSSL_EVP_PKEY structure.
 *
 * @param [in, out] out   Pointer to new WOLFSSL_EVP_PKEY structure.
 *                        Can be NULL.
 * @param [in, out] in    DER buffer to convert.
 * @param [in]      inSz  Size of in buffer.
 * @return  Pointer to a new WOLFSSL_EVP_PKEY structure on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PUBKEY(WOLFSSL_EVP_PKEY** out,
    const unsigned char** in, long inSz)
{
    WOLFSSL_ENTER("wolfSSL_d2i_PUBKEY");
    return d2i_evp_pkey_try(out, in, inSz, 0);
}

#ifndef NO_BIO
/* Converts a DER encoded public key in a BIO to a WOLFSSL_EVP_PKEY structure.
 *
 * @param [in]  bio  BIO to read DER from.
 * @param [out] out  New WOLFSSL_EVP_PKEY pointer when not NULL.
 * @return  Pointer to a new WOLFSSL_EVP_PKEY structure on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PUBKEY_bio(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY** out)
{
    unsigned char* mem;
    long memSz;
    WOLFSSL_EVP_PKEY* pkey = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_PUBKEY_bio");

    /* Validate parameters. */
    if (bio == NULL) {
        return NULL;
    }

    /* Get length of data in BIO. */
    memSz = wolfSSL_BIO_get_len(bio);
    if (memSz <= 0) {
        return NULL;
    }
    /* Allocate memory to read all of BIO data into. */
    mem = (unsigned char*)XMALLOC((size_t)memSz, bio->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        return NULL;
    }
    /* Read all data into allocated buffer. */
    if (wolfSSL_BIO_read(bio, mem, (int)memSz) == memSz) {
        /* Create a WOLFSSL_EVP_PKEY from data. */
        pkey = wolfSSL_d2i_PUBKEY(NULL, (const unsigned char**)&mem, memSz);
        if (out != NULL && pkey != NULL) {
            /* Return new WOLFSSL_EVP_PKEY through parameter. */
            *out = pkey;
        }
    }

    /* Dispose of memory holding BIO data. */
    XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return pkey;
}
#endif /* !NO_BIO */
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || \
    defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_QT) || defined(WOLFSSL_WPAS_SMALL)
/* Converts a DER encoded private key to a WOLFSSL_EVP_PKEY structure.
 *
 * @param [in, out] out   Pointer to new WOLFSSL_EVP_PKEY structure.
 *                        Can be NULL.
 * @param [in, out] in    DER buffer to convert.
 * @param [in]      inSz  Size of in buffer.
 * @return  Pointer to a new WOLFSSL_EVP_PKEY structure on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_EVP(WOLFSSL_EVP_PKEY** out,
    unsigned char** in, long inSz)
{
    WOLFSSL_ENTER("wolfSSL_d2i_PrivateKey_EVP");
    return d2i_evp_pkey_try(out, (const unsigned char**)in, inSz, 1);
}
#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_QT ||
        * WOLFSSL_WPAS_SMALL*/

#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || \
    defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_QT)

#ifndef NO_BIO
/* Converts a DER encoded private key in a BIO to a WOLFSSL_EVP_PKEY structure.
 *
 * @param [in]  bio  BIO to read DER from.
 * @param [out] out  New WOLFSSL_EVP_PKEY pointer when not NULL.
 * @return  Pointer to a new WOLFSSL_EVP_PKEY structure on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_bio(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY** out)
{
    unsigned char* mem = NULL;
    int memSz = 0;
    WOLFSSL_EVP_PKEY* key = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_PrivateKey_bio");

    /* Validate parameters. */
    if (bio == NULL) {
        return NULL;
    }

    /* Get length of data in BIO. */
    memSz = wolfSSL_BIO_get_len(bio);
    if (memSz <= 0) {
        WOLFSSL_MSG("wolfSSL_BIO_get_len() failure");
        return NULL;
    }
    /* Allocate memory to read all of BIO data into. */
    mem = (unsigned char*)XMALLOC((size_t)memSz, bio->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        WOLFSSL_MSG("Malloc failure");
        return NULL;
    }

    /* Read all of data. */
    if (wolfSSL_BIO_read(bio, (unsigned char*)mem, memSz) == memSz) {
        /* Determines key type and returns the new private EVP_PKEY object */
        if ((key = wolfSSL_d2i_PrivateKey_EVP(NULL, &mem, (long)memSz)) ==
                NULL) {
            WOLFSSL_MSG("wolfSSL_d2i_PrivateKey_EVP() failure");
            XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
            return NULL;
        }

        /* Write extra data back into bio object if necessary. */
        if (memSz > key->pkey_sz) {
            wolfSSL_BIO_write(bio, mem + key->pkey_sz, memSz - key->pkey_sz);
            if (wolfSSL_BIO_get_len(bio) <= 0) {
                WOLFSSL_MSG("Failed to write memory to bio");
                XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
                return NULL;
            }
        }

        /* Return key through parameter if required. */
        if (out != NULL) {
            *out = key;
        }
    }

    /* Dispose of memory holding BIO data. */
    XFREE(mem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return key;
}
#endif /* !NO_BIO */

#endif /* OPENSSL_ALL || WOLFSSL_ASIO || WOLFSSL_HAPROXY || WOLFSSL_NGINX ||
        * WOLFSSL_QT */

#ifdef OPENSSL_EXTRA
/* Reads in a DER format key. If PKCS8 headers are found they are stripped off.
 *
 * @param [in]      type  Type of key.
 * @param [in, out] out   Newly created WOLFSSL_EVP_PKEY structure.
 * @param [in, out] in    Pointer to input key DER.
 *                        Pointer is advanced the same number of bytes read on
 *                        success.
 * @param [in]      inSz  Size of in buffer.
 * @return  A non null pointer on success.
 * @return  NULL on failure.
 */
static WOLFSSL_EVP_PKEY* d2i_evp_pkey(int type, WOLFSSL_EVP_PKEY** out,
    const unsigned char **in, long inSz, int priv)
{
    int ret = 0;
    word32 idx = 0, algId;
    word16 pkcs8HeaderSz = 0;
    WOLFSSL_EVP_PKEY* local;
    const unsigned char* p;
    int opt;

    (void)opt;

    /* Validate parameters. */
    if (in == NULL || inSz < 0) {
        WOLFSSL_MSG("Bad argument");
        return NULL;
    }

    if (priv == 1) {
        /* Check if input buffer has PKCS8 header. In the case that it does not
         * have a PKCS8 header then do not error out. */
        if ((ret = ToTraditionalInline_ex((const byte*)(*in), &idx,
                (word32)inSz, &algId)) > 0) {
            WOLFSSL_MSG("Found PKCS8 header");
            pkcs8HeaderSz = (word16)idx;

            /* Check header algorithm id matches algorithm type passed in. */
            if ((type == WC_EVP_PKEY_RSA && algId != RSAk
            #ifdef WC_RSA_PSS
                 && algId != RSAPSSk
            #endif
                 ) ||
                (type == WC_EVP_PKEY_EC && algId != ECDSAk) ||
                (type == WC_EVP_PKEY_DSA && algId != DSAk) ||
                (type == WC_EVP_PKEY_DH && algId != DHk)) {
                WOLFSSL_MSG("PKCS8 does not match EVP key type");
                return NULL;
            }

            (void)idx; /* not used */
        }
        /* Ensure no error occurred try to remove any PKCS#8 header. */
        else if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WOLFSSL_MSG("Unexpected error with trying to remove PKCS8 header");
            return NULL;
        }
    }

    /* Dispose of any WOLFSSL_EVP_PKEY passed in. */
    if (out != NULL && *out != NULL) {
        wolfSSL_EVP_PKEY_free(*out);
        *out = NULL;
    }
    /* Create a new WOLFSSL_EVP_PKEY and populate. */
    local = wolfSSL_EVP_PKEY_new();
    if (local == NULL) {
        return NULL;
    }
    local->type          = type;
    local->pkey_sz       = (int)inSz;
    local->pkcs8HeaderSz = pkcs8HeaderSz;
    local->pkey.ptr      = (char*)XMALLOC((size_t)inSz, NULL,
                                          DYNAMIC_TYPE_PUBLIC_KEY);
    if (local->pkey.ptr == NULL) {
        wolfSSL_EVP_PKEY_free(local);
        return NULL;
    }
    XMEMCPY(local->pkey.ptr, *in, (size_t)inSz);
    p = (const unsigned char*)local->pkey.ptr;

    /* Create an algorithm specific object into WOLFSSL_EVP_PKEY. */
    switch (type) {
#ifndef NO_RSA
        case WC_EVP_PKEY_RSA:
            /* Create a WOLFSSL_RSA object. */
            local->ownRsa = 1;
            opt = priv ? WOLFSSL_RSA_LOAD_PRIVATE : WOLFSSL_RSA_LOAD_PUBLIC;
            local->rsa = wolfssl_rsa_d2i(NULL, p, local->pkey_sz, opt);
            if (local->rsa == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* NO_RSA */
#ifdef HAVE_ECC
        case WC_EVP_PKEY_EC:
            /* Create a WOLFSSL_EC object. */
            local->ownEcc = 1;
            local->ecc = wolfSSL_EC_KEY_new();
            if (local->ecc == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            opt = priv ? WOLFSSL_EC_KEY_LOAD_PRIVATE :
                         WOLFSSL_EC_KEY_LOAD_PUBLIC;
            if (wolfSSL_EC_KEY_LoadDer_ex(local->ecc, p, local->pkey_sz, opt) !=
                    WOLFSSL_SUCCESS) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* HAVE_ECC */
#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || defined(WOLFSSL_OPENSSH)
#ifndef NO_DSA
        case WC_EVP_PKEY_DSA:
            /* Create a WOLFSSL_DSA object. */
            local->ownDsa = 1;
            local->dsa = wolfSSL_DSA_new();
            if (local->dsa == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            opt = priv ? WOLFSSL_DSA_LOAD_PRIVATE : WOLFSSL_DSA_LOAD_PUBLIC;
            if (wolfSSL_DSA_LoadDer_ex(local->dsa, p, local->pkey_sz, opt) !=
                    WOLFSSL_SUCCESS) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* NO_DSA */
#ifndef NO_DH
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION>2))
        case WC_EVP_PKEY_DH:
            /* Create a WOLFSSL_DH object. */
            local->ownDh = 1;
            local->dh = wolfSSL_DH_new();
            if (local->dh == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            if (wolfSSL_DH_LoadDer(local->dh, p, local->pkey_sz) !=
                    WOLFSSL_SUCCESS) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* HAVE_DH */
#endif /* WOLFSSL_QT || OPENSSL_ALL || WOLFSSL_OPENSSH */
        default:
            WOLFSSL_MSG("Unsupported key type");
            wolfSSL_EVP_PKEY_free(local);
            return NULL;
    }

    /* Advance pointer and return through parameter when required on success. */
    if (local != NULL) {
        if (local->pkey_sz <= (int)inSz) {
            *in += local->pkey_sz;
        }
        if (out != NULL) {
            *out = local;
        }
    }

    /* Return newly allocated WOLFSSL_EVP_PKEY structure. */
    return local;
}

/* Reads in a DER format key.
 *
 * @param [in]      type  Type of key.
 * @param [in, out] out   Newly created WOLFSSL_EVP_PKEY structure.
 * @param [in, out] in    Pointer to input key DER.
 *                        Pointer is advanced the same number of bytes read on
 *                        success.
 * @param [in]      inSz  Size of in buffer.
 * @return  A non null pointer on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PublicKey(int type, WOLFSSL_EVP_PKEY** out,
        const unsigned char **in, long inSz)
{
    WOLFSSL_ENTER("wolfSSL_d2i_PublicKey");

    return d2i_evp_pkey(type, out, in, inSz, 0);
}

/* Reads in a DER format key. If PKCS8 headers are found they are stripped off.
 *
 * @param [in]      type  Type of key.
 * @param [in, out] out   Newly created WOLFSSL_EVP_PKEY structure.
 * @param [in, out] in    Pointer to input key DER.
 *                        Pointer is advanced the same number of bytes read on
 *                        success.
 * @param [in]      inSz  Size of in buffer.
 * @return  A non null pointer on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey(int type, WOLFSSL_EVP_PKEY** out,
        const unsigned char **in, long inSz)
{
    WOLFSSL_ENTER("wolfSSL_d2i_PrivateKey");

    return d2i_evp_pkey(type, out, in, inSz, 1);
}
#endif /* OPENSSL_EXTRA */

#ifdef OPENSSL_ALL
/* Detect RSA or EC key and decode private key DER.
 *
 * @param [in, out] pkey    Newly created WOLFSSL_EVP_PKEY structure.
 * @param [in, out] pp      Pointer to private key DER data.
 * @param [in]      length  Length in bytes of DER data.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_AutoPrivateKey(WOLFSSL_EVP_PKEY** pkey,
    const unsigned char** pp, long length)
{
    int ret;
    WOLFSSL_EVP_PKEY* key = NULL;
    const byte* der = *pp;
    word32 idx = 0;
    int len = 0;
    int cnt = 0;
    word32 algId;
    word32 keyLen = (word32)length;

    /* Take off PKCS#8 wrapper if found. */
    if ((len = ToTraditionalInline_ex(der, &idx, keyLen, &algId)) >= 0) {
        der += idx;
        keyLen = (word32)len;
    }

    idx = 0;
    len = 0;
    /* Use the number of elements in the outer sequence to determine key type.
     */
    ret = GetSequence(der, &idx, &len, keyLen);
    if (ret >= 0) {
        word32 end = idx + (word32)len;
        while (ret >= 0 && idx < end) {
            /* Skip type */
            idx++;
            /* Get length and skip over - keeping count */
            len = 0;
            ret = GetLength(der, &idx, &len, keyLen);
            if (ret >= 0) {
                if (idx + (word32)len > end) {
                    ret = ASN_PARSE_E;
                }
                else {
                    idx += (word32)len;
                    cnt++;
                }
            }
        }
    }

    if (ret >= 0) {
        int type;
        /* ECC includes version, private[, curve][, public key] */
        if (cnt >= 2 && cnt <= 4) {
            type = WC_EVP_PKEY_EC;
        }
        else {
            type = WC_EVP_PKEY_RSA;
        }

        /* Decode the detected type of private key. */
        key = wolfSSL_d2i_PrivateKey(type, pkey, &der, keyLen);
        /* Update the pointer to after the DER data. */
        *pp = der;
    }

    return key;
}

#if !defined(NO_BIO) && !defined(NO_PWDBASED) && defined(HAVE_PKCS8)
/* Read all of the BIO data into a newly allocated buffer.
 *
 * @param [in]  bio   BIO to read from.
 * @param [out] data  Allocated buffer holding all BIO data.
 * @return  Number of bytes allocated and read.
 * @return  MEMORY_E on dynamic memory allocation failure.
 * @return  Other negative on error.
 */
static int bio_get_data(WOLFSSL_BIO* bio, byte** data)
{
    int ret = 0;
    byte* mem = NULL;

    /* Get length of data in BIO. */
    ret = wolfSSL_BIO_get_len(bio);
    if (ret > 0) {
        /* Allocate memory big enough to hold data in BIO. */
        mem = (byte*)XMALLOC((size_t)ret, bio->heap, DYNAMIC_TYPE_OPENSSL);
        if (mem == NULL) {
            WOLFSSL_MSG("Memory error");
            ret = MEMORY_E;
        }
        if (ret >= 0) {
            /* Read data from BIO. */
            if ((ret = wolfSSL_BIO_read(bio, mem, ret)) <= 0) {
                XFREE(mem, bio->heap, DYNAMIC_TYPE_OPENSSL);
                ret = MEMORY_E;
                mem = NULL;
            }
        }
    }

    /* Return allocated buffer with data from BIO. */
    *data = mem;
    return ret;
}

/* Convert the algorithm id to a key type.
 *
 * @param [in] algId  Algorithm Id.
 * @return  Key type on success.
 * @return  WC_EVP_PKEY_NONE when algorithm id not supported.
 */
static int wolfssl_i_alg_id_to_key_type(word32 algId)
{
    int type;

    /* Convert algorithm id into EVP PKEY id. */
    switch (algId) {
#ifndef NO_RSA
        case RSAk:
    #ifdef WC_RSA_PSS
        case RSAPSSk:
    #endif
            type = WC_EVP_PKEY_RSA;
            break;
#endif
    #ifdef HAVE_ECC
        case ECDSAk:
            type = WC_EVP_PKEY_EC;
            break;
    #endif
    #ifndef NO_DSA
        case DSAk:
            type = WC_EVP_PKEY_DSA;
            break;
    #endif
    #ifndef NO_DH
        case DHk:
            type = WC_EVP_PKEY_DH;
            break;
    #endif
        default:
            WOLFSSL_MSG("PKEY algorithm, from PKCS#8 header, not supported");
            type = WC_EVP_PKEY_NONE;
            break;
    }

    return type;
}

/* Creates an WOLFSSL_EVP_PKEY from PKCS#8 encrypted private DER in a BIO.
 *
 * Uses the PEM default password callback when cb is NULL.
 *
 * @param [in]      bio   BIO to read DER from.
 * @param [in, out] pkey  Newly created WOLFSSL_EVP_PKEY structure.
 * @param [in]      cb    Password callback. May be NULL.
 * @param [in]      ctx   Password callback context. May be NULL.
 * @return  A non null pointer on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PKCS8PrivateKey_bio(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY** pkey, wc_pem_password_cb* cb, void* ctx)
{
    int ret;
    const byte* p;
    byte* der = NULL;
    int len;
    word32 algId;
    WOLFSSL_EVP_PKEY* key;
    int type;
    char password[NAME_SZ];
    int passwordSz;

    /* Get the data from the BIO into a newly allocated buffer. */
    if ((len = bio_get_data(bio, &der)) < 0)
        return NULL;

    /* Use the PEM default callback if none supplied. */
    if (cb == NULL) {
        cb = wolfSSL_PEM_def_callback;
    }
    /* Get the password. */
    passwordSz = cb(password, sizeof(password), PEM_PASS_READ, ctx);
    if (passwordSz < 0) {
        XFREE(der, bio->heap, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("wolfSSL_d2i_PKCS8PrivateKey_bio password", password,
        passwordSz);
#endif

    /* Decrypt the PKCS#8 encrypted private key and get algorithm. */
    ret = ToTraditionalEnc(der, (word32)len, password, passwordSz, &algId);
    ForceZero(password, (word32)passwordSz);
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(password, passwordSz);
#endif
    if (ret < 0) {
        XFREE(der, bio->heap, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }

    /* Get the key type from the algorithm id of the PKCS#8 header. */
    if ((type = wolfssl_i_alg_id_to_key_type(algId)) == WC_EVP_PKEY_NONE) {
        XFREE(der, bio->heap, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }

    /* Decode private key with the known type. */
    p = der;
    key = d2i_evp_pkey(type, pkey, &p, len, 1);

    /* Dispose of memory holding BIO data. */
    XFREE(der, bio->heap, DYNAMIC_TYPE_OPENSSL);
    return key;
}
#endif /* !NO_BIO && !NO_PWDBASED && HAVE_PKCS8 */
#endif /* OPENSSL_ALL */

#ifdef OPENSSL_EXTRA
/* Reads in a PKCS#8 DER format key.
 *
 * @param [in, out] pkey    Newly created WOLFSSL_PKCS8_PRIV_KEY_INFO structure.
 * @param [in, out] keyBuf  Pointer to input key DER.
 *                          Pointer is advanced the same number of bytes read on
 *                          success.
 * @param [in]      keyLen  Number of bytes in keyBuf.
 * @return  A non null pointer on success.
 * @return  NULL on failure.
 */
WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_d2i_PKCS8_PKEY(
    WOLFSSL_PKCS8_PRIV_KEY_INFO** pkey, const unsigned char** keyBuf,
    long keyLen)
{
    WOLFSSL_PKCS8_PRIV_KEY_INFO* pkcs8 = NULL;
#ifdef WOLFSSL_PEM_TO_DER
    int ret;
    DerBuffer* pkcs8Der = NULL;
    DerBuffer rawDer;
    EncryptedInfo info;
    int advanceLen = 0;

    /* Clear the encryption information and DER buffer. */
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&rawDer, 0, sizeof(rawDer));

    /* Validate parameters. */
    if ((keyBuf == NULL) || (*keyBuf == NULL) || (keyLen <= 0)) {
        WOLFSSL_MSG("Bad key PEM/DER args");
        return NULL;
    }

    /* Try to decode the PEM into DER. */
    ret = PemToDer(*keyBuf, keyLen, PRIVATEKEY_TYPE, &pkcs8Der, NULL, &info,
        NULL);
    if (ret >= 0) {
        /* Cache the amount of data in PEM formatted private key. */
        advanceLen = (int)info.consumed;
    }
    else {
        /* Not PEM - create a DerBuffer with the PKCS#8 DER data. */
        WOLFSSL_MSG("Not PEM format");
        ret = AllocDer(&pkcs8Der, (word32)keyLen, PRIVATEKEY_TYPE, NULL);
        if (ret == 0) {
            XMEMCPY(pkcs8Der->buffer, *keyBuf, keyLen);
        }
    }

    if (ret == 0) {
        /* Verify this is PKCS8 Key */
        word32 inOutIdx = 0;
        word32 algId;

        ret = ToTraditionalInline_ex(pkcs8Der->buffer, &inOutIdx,
            pkcs8Der->length, &algId);
        if (ret >= 0) {
            if (advanceLen == 0) {
                /* Set only if not PEM */
                advanceLen = (int)inOutIdx + ret;
            }
            if (algId == DHk) {
                /* Special case for DH as we expect the DER buffer to be always
                 * be in PKCS8 format */
                rawDer.buffer = pkcs8Der->buffer;
                rawDer.length = inOutIdx + (word32)ret;
            }
            else {
                rawDer.buffer = pkcs8Der->buffer + inOutIdx;
                rawDer.length = (word32)ret;
            }
            ret = 0; /* good DER */
        }
    }

    if (ret == 0) {
        /* Create a WOLFSSL_EVP_PKEY for a WOLFSSL_PKCS8_PRIV_KEY_INFO. */
        pkcs8 = wolfSSL_EVP_PKEY_new();
        if (pkcs8 == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        /* Allocate memory to hold DER. */
        pkcs8->pkey.ptr = (char*)XMALLOC(rawDer.length, NULL,
            DYNAMIC_TYPE_PUBLIC_KEY);
        if (pkcs8->pkey.ptr == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        /* Copy in DER data and size. */
        XMEMCPY(pkcs8->pkey.ptr, rawDer.buffer, rawDer.length);
        pkcs8->pkey_sz = (int)rawDer.length;
    }

    /* Dispose of PKCS#8 DER data - raw DER reference data in pkcs8Der. */
    FreeDer(&pkcs8Der);
    if (ret != 0) {
        /* Dispose of WOLFSSL_PKCS8_PRIV_KEY_INFO object on error. */
        wolfSSL_EVP_PKEY_free(pkcs8);
        pkcs8 = NULL;
    }
    else {
        /* Advance the buffer past the key on success. */
        *keyBuf += advanceLen;
    }
    if (pkey != NULL) {
        /* Return the WOLFSSL_PKCS8_PRIV_KEY_INFO object through parameter. */
        *pkey = pkcs8;
    }
#else
    (void)pkey;
    (void)keyBuf;
    (void)keyLen;
#endif /* WOLFSSL_PEM_TO_DER */

    /* Return new WOLFSSL_PKCS8_PRIV_KEY_INFO object. */
    return pkcs8;
}

#ifndef NO_BIO
/* Converts a DER format key read from BIO to a PKCS#8 structure.
 *
 * @param [in]  bio  Input BIO to read DER from.
 * @param [out] pkey If not NULL then this pointer will be overwritten with a
 *                   new PKCS8 structure.
 * @return  A WOLFSSL_PKCS8_PRIV_KEY_INFO pointer on success
 * @return  NULL on failure.
 */
WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_d2i_PKCS8_PKEY_bio(WOLFSSL_BIO* bio,
    WOLFSSL_PKCS8_PRIV_KEY_INFO** pkey)
{
    WOLFSSL_PKCS8_PRIV_KEY_INFO* pkcs8 = NULL;
#ifdef WOLFSSL_PEM_TO_DER
    unsigned char* mem = NULL;
    int memSz;

    WOLFSSL_ENTER("wolfSSL_d2i_PKCS8_PKEY_bio");

    /* Validate parameters. */
    if (bio == NULL) {
        return NULL;
    }

    /* Get the memory buffer from the BIO. */
    if ((memSz = wolfSSL_BIO_get_mem_data(bio, &mem)) < 0) {
        return NULL;
    }

    /* Decode the PKCS#8 key into a WOLFSSL_PKCS8_PRIV_KEY_INFO object. */
    pkcs8 = wolfSSL_d2i_PKCS8_PKEY(pkey, (const unsigned char**)&mem, memSz);
#else
    (void)bio;
    (void)pkey;
#endif /* WOLFSSL_PEM_TO_DER */

    /* Return new WOLFSSL_PKCS8_PRIV_KEY_INFO object. */
    return pkcs8;
}
#endif /* !NO_BIO */

#ifdef WOLF_PRIVATE_KEY_ID
/* Create an EVP structure for use with crypto callbacks.
 *
 * @param [in]  type   Type of private key.
 * @param [out] out    WOLFSSL_EVP_PKEY object created.
 * @param [in]  heap   Heap hint for dynamic memory allocation.
 * @param [in]  devId  Device id.
 * @return  A new WOLFSSL_EVP_PKEY object on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_id(int type, WOLFSSL_EVP_PKEY** out,
    void* heap, int devId)
{
    WOLFSSL_EVP_PKEY* local;

    /* Dispose of any object passed in through out. */
    if (out != NULL && *out != NULL) {
        wolfSSL_EVP_PKEY_free(*out);
        *out = NULL;
    }

    /* Create a local WOLFSSL_EVP_PKEY to be decoded into. */
    local = wolfSSL_EVP_PKEY_new_ex(heap);
    if (local == NULL) {
        return NULL;
    }
    local->type          = type;
    local->pkey_sz       = 0;
    local->pkcs8HeaderSz = 0;

    switch (type) {
#ifndef NO_RSA
        case WC_EVP_PKEY_RSA:
        {
            /* Create a WOLFSSL_RSA object into WOLFSSL_EVP_PKEY. */
            local->rsa = wolfSSL_RSA_new_ex(heap, devId);
            if (local->rsa == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            local->ownRsa = 1;
            /* Algorithm specific object set into WOLFSL_EVP_PKEY. */
            local->rsa->inSet = 1;
        #ifdef WOLF_CRYPTO_CB
            ((RsaKey*)local->rsa->internal)->devId = devId;
        #endif
            break;
        }
#endif /* !NO_RSA */
#ifdef HAVE_ECC
        case WC_EVP_PKEY_EC:
        {
            ecc_key* key;

            /* Create a WOLFSSL_EC object into WOLFSSL_EVP_PKEY. */
            local->ecc = wolfSSL_EC_KEY_new_ex(heap, devId);
            if (local->ecc == NULL) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            local->ownEcc = 1;
            /* Algorithm specific object set into WOLFSL_EVP_PKEY. */
            local->ecc->inSet = 1;

            /* Get wolfSSL EC key and set fields. */
            key = (ecc_key*)local->ecc->internal;
        #ifdef WOLF_CRYPTO_CB
            key->devId = devId;
        #endif
            key->type = ECC_PRIVATEKEY;
            /* key is required to have a key size / curve set, although
             * actual one used is determined by devId callback function. */
            wc_ecc_set_curve(key, ECDHE_SIZE, ECC_CURVE_DEF);
            break;
        }
#endif /* HAVE_ECC */
        default:
            WOLFSSL_MSG("Unsupported private key id type");
            wolfSSL_EVP_PKEY_free(local);
            return NULL;
    }

    /* Return new WOLFSSL_EVP_PKEY through parameter if required. */
    if (local != NULL && out != NULL) {
        *out = local;
    }
    /* Return new WOLFSSL_EVP_PKEY. */
    return local;
}
#endif /* WOLF_PRIVATE_KEY_ID */
#endif /* OPENSSL_EXTRA */

/*******************************************************************************
 * END OF d2i APIs
 ******************************************************************************/

/*******************************************************************************
 * START OF i2d APIs
 ******************************************************************************/

#ifdef OPENSSL_ALL
/* Encode PKCS#8 key as DER data.
 *
 * @param [in]  key  PKCS#8 private key to encode.
 * @param [out] pp   Pointer to buffer of encoded data.
 * @return  Length of DER encoded data on success.
 * @return  Less than zero on failure.
 */
int wolfSSL_i2d_PKCS8_PKEY(WOLFSSL_PKCS8_PRIV_KEY_INFO* key, unsigned char** pp)
{
    word32 keySz = 0;
    unsigned char* out;
    int len;

    WOLFSSL_ENTER("wolfSSL_i2d_PKCS8_PKEY");

    /* Validate parameters. */
    if (key == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* Get the length of DER encoding. */
    if (pkcs8_encode(key, NULL, &keySz) != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
        return WOLFSSL_FATAL_ERROR;
    }
    len = (int)keySz;

    /* Return the length when output parameter is NULL. */
    if ((pp == NULL) || (len == 0)) {
        return len;
    }

    /* Allocate memory for DER encoding if NULL passed in for output buffer. */
    if (*pp == NULL) {
        out = (unsigned char*)XMALLOC((size_t)len, NULL, DYNAMIC_TYPE_ASN1);
        if (out == NULL) {
            return WOLFSSL_FATAL_ERROR;
        }
    }
    else {
        /* Use buffer passed in - assume it is big enough. */
        out = *pp;
    }

    /* Encode the PKCS#8 key into the output buffer. */
    if (pkcs8_encode(key, out, &keySz) != len) {
        if (*pp == NULL) {
            XFREE(out, NULL, DYNAMIC_TYPE_ASN1);
        }
        return WOLFSSL_FATAL_ERROR;
    }

    /* Return new output buffer or move pointer passed encoded data. */
    if (*pp == NULL) {
        *pp = out;
    }
    else {
        *pp += len;
    }

    return len;
}
#endif

#ifdef OPENSSL_EXTRA

#if !defined(NO_ASN) && !defined(NO_PWDBASED)
/* Get raw pointer to DER buffer from WOLFSSL_EVP_PKEY.
 *
 * Assumes der is large enough if passed in.
 *
 * @param [in]  key  WOLFSSL_EVP_PKEY to get DER buffer for.
 * @param [out] der  Buffer holding DER encoding. May be NULL.
 * @return  Size of DER encoding on success.
 * @return  Less than 0 on failure.
 */
static int wolfssl_i_evp_pkey_get_der(const WOLFSSL_EVP_PKEY* key,
    unsigned char** der)
{
    int sz;
    word16 pkcs8HeaderSz;

    /* Validate parameters. */
    if ((key == NULL) || (key->pkey_sz == 0)) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* If pkcs8HeaderSz is invalid, return all of the DER encoding. */
    pkcs8HeaderSz = 0;
    if (key->pkey_sz > key->pkcs8HeaderSz) {
        pkcs8HeaderSz = key->pkcs8HeaderSz;
    }
    /* Calculate the size of the DER encoding to return. */
    sz = key->pkey_sz - pkcs8HeaderSz;
    /* Returning encoding when DER is not NULL. */
    if (der != NULL) {
        unsigned char* pt = (unsigned char*)key->pkey.ptr;
        int bufferPassedIn = ((*der) != NULL);

        if (!bufferPassedIn) {
            /* Allocate buffer to hold DER encoding. */
            *der = (unsigned char*)XMALLOC((size_t)sz, NULL,
                DYNAMIC_TYPE_OPENSSL);
            if (*der == NULL) {
                return WOLFSSL_FATAL_ERROR;
            }
        }
        /* Copy in non-PKCS#8 DER encoding. */
        XMEMCPY(*der, pt + pkcs8HeaderSz, (size_t)sz);
        /* Step past encoded key when buffer provided. */
        if (bufferPassedIn) {
            *der += sz;
        }
    }

    /* Return size of DER encoded data. */
    return sz;
}

/* Encode key as unencrypted DER data.
 *
 * @param [in]  key  PKCS#8 private key to encode.
 * @param [out] der  Pointer to buffer of encoded data.
 * @return  Length of DER encoded data on success.
 * @return  Less than zero on failure.
 */
int wolfSSL_i2d_PrivateKey(const WOLFSSL_EVP_PKEY* key, unsigned char** der)
{
    return wolfssl_i_evp_pkey_get_der(key, der);
}

#ifndef NO_BIO
/* Encode key as unencrypted DER data and write to BIO.
 *
 * @param [in]  bio  BIO to write data to.
 * @param [in]  key  PKCS#8 private key to encode.
 * @return  Length of DER encoded data on success.
 * @return  Less than zero on failure.
 */
int wolfSSL_i2d_PrivateKey_bio(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* key)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    int derSz = 0;
    byte* der = NULL;

    if (bio == NULL || key == NULL) {
        return WOLFSSL_FAILURE;
    }

    derSz = wolfSSL_i2d_PrivateKey(key, &der);
    if (derSz <= 0) {
        WOLFSSL_MSG("wolfSSL_i2d_PrivateKey (for getting size) failed");
        return WOLFSSL_FAILURE;
    }

    if (wolfSSL_BIO_write(bio, der, derSz) != derSz) {
        goto cleanup;
    }

    ret = WOLFSSL_SUCCESS;

cleanup:
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    return ret;
}
#endif

#ifdef HAVE_ECC
/* Encode EC key as public key DER.
 *
 * @param [in]  key  WOLFSSL_EVP_KEY object to encode.
 * @param [in]  ec   WOLFSSL_EC_KEY object to encode.
 * @param [out] der  Buffer with DER encoding of EC public key.
 * @return  Public key DER encoding size on success.
 * @return  WOLFSSL_FATAL_ERROR when dynamic memory allocation fails.
 * @return  WOLFSSL_FATAL_ERROR when encoding fails.
 */
static int wolfssl_i_i2d_ecpublickey(const WOLFSSL_EVP_PKEY* key,
    const WOLFSSL_EC_KEY *ec, unsigned char **der)
{
    word32 pub_derSz = 0;
    int ret;
    unsigned char *local_der = NULL;
    word32 local_derSz = 0;
    unsigned char *pub_der = NULL;
    ecc_key *eccKey = NULL;
    word32 inOutIdx = 0;

    /* We need to get the DER, then convert it to a public key. But what we get
     * might be a buffered private key so we need to decode it and then encode
     * the public part. */
    ret = wolfssl_i_evp_pkey_get_der(key, &local_der);
    if (ret <= 0) {
        /* In this case, there was no buffered DER at all. This could be the
         * case where the key that was passed in was generated. So now we
         * have to create the local DER. */
        local_derSz = (word32)wolfSSL_i2d_ECPrivateKey(ec, &local_der);
        if (local_derSz == 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    } else {
        local_derSz = (word32)ret;
        ret = 0;
    }

    if (ret == 0) {
        eccKey = (ecc_key *)XMALLOC(sizeof(*eccKey), NULL, DYNAMIC_TYPE_ECC);
        if (eccKey == NULL) {
            WOLFSSL_MSG("Failed to allocate key buffer.");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    /* Initialize a wolfCrypt ECC key. */
    if (ret == 0) {
        ret = wc_ecc_init(eccKey);
    }
    if (ret == 0) {
        /* Decode the DER data with wolfCrypt ECC key. */
        ret = wc_EccPublicKeyDecode(local_der, &inOutIdx, eccKey, local_derSz);
        if (ret < 0) {
            /* We now try again as x.963 [point type][x][opt y]. */
            ret = wc_ecc_import_x963(local_der, local_derSz, eccKey);
        }
    }

    if (ret == 0) {
        /* Get the size of the encoding of the public key DER. */
        pub_derSz = (word32)wc_EccPublicKeyDerSize(eccKey, 1);
        if ((int)pub_derSz <= 0) {
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == 0) {
        /* Allocate memory for public key DER encoding. */
        pub_der = (unsigned char*)XMALLOC(pub_derSz, NULL,
            DYNAMIC_TYPE_PUBLIC_KEY);
        if (pub_der == NULL) {
            WOLFSSL_MSG("Failed to allocate output buffer.");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        /* Encode public key as DER. */
        pub_derSz = (word32)wc_EccPublicKeyToDer(eccKey, pub_der, pub_derSz, 1);
        if ((int)pub_derSz <= 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    /* This block is for actually returning the DER of the public key */
    if ((ret == 0) && (der != NULL)) {
        int bufferPassedIn = ((*der) != NULL);
        if (!bufferPassedIn) {
            *der = (unsigned char*)XMALLOC(pub_derSz, NULL,
                DYNAMIC_TYPE_PUBLIC_KEY);
            if (*der == NULL) {
                WOLFSSL_MSG("Failed to allocate output buffer.");
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
        if (ret == 0) {
            XMEMCPY(*der, pub_der, pub_derSz);
            if (bufferPassedIn) {
                *der += pub_derSz;
            }
        }
    }

    /* Dispose of allocated objects. */
    XFREE(pub_der, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(local_der, NULL, DYNAMIC_TYPE_OPENSSL);
    wc_ecc_free(eccKey);
    XFREE(eccKey, NULL, DYNAMIC_TYPE_ECC);

    /* Return error or the size of the DER encoded public key. */
    if (ret == 0) {
        ret = (int)pub_derSz;
    }
    return ret;
}
#endif

/* Encode the WOLFSSL_EVP_PKEY object as public key DER.
 *
 * @param [in]  key  WOLFSLS_EVP_PKEY object to encode.
 * @param [out] der  Buffer with DER encoding of public key.
 * @return  Public key DER encoding size on success.
 * @return  WOLFSSL_FATAL_ERROR when key is NULL.
 * @return  WOLFSSL_FATAL_ERROR when key type not supported.
 * @return  WOLFSSL_FATAL_ERROR when dynamic memory allocation fails.
 */
int wolfSSL_i2d_PublicKey(const WOLFSSL_EVP_PKEY *key, unsigned char **der)
{
    int ret;

    /* Validate parameters. */
    if (key == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* Encode based on key type. */
    switch (key->type) {
    #ifndef NO_RSA
        case WC_EVP_PKEY_RSA:
            return wolfSSL_i2d_RSAPublicKey(key->rsa, der);
    #endif
    #ifdef HAVE_ECC
        case WC_EVP_PKEY_EC:
            return wolfssl_i_i2d_ecpublickey(key, key->ecc, der);
    #endif
        default:
            ret = WOLFSSL_FATAL_ERROR;
            break;
    }

    return ret;
}

/* Encode the WOLFSSL_EVP_PKEY object as public key DER.
 *
 * @param [in]  key  WOLFSLS_EVP_PKEY object to encode.
 * @param [out] der  Buffer with DER encoding of public key.
 * @return  Public key DER encoding size on success.
 * @return  WOLFSSL_FATAL_ERROR when key is NULL.
 * @return  WOLFSSL_FATAL_ERROR when key type not supported.
 * @return  WOLFSSL_FATAL_ERROR when dynamic memory allocation fails.
 */
int wolfSSL_i2d_PUBKEY(const WOLFSSL_EVP_PKEY *key, unsigned char **der)
{
    return wolfSSL_i2d_PublicKey(key, der);
}
#endif /* !NO_ASN && !NO_PWDBASED */

#endif /* OPENSSL_EXTRA */

#endif /* !NO_CERTS */

/*******************************************************************************
 * END OF i2d APIs
 ******************************************************************************/

#endif /* !WOLFSSL_EVP_PK_INCLUDED */

