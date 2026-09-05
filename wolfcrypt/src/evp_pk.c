/* evp_pk.c
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
    char* prevData = NULL;
    int prevSz = 0;
    int ret = 1;

    (void)priv;

    /* Get or create the EVP PKEY object. */
    if (*out != NULL) {
        pkey = *out;
        /* Hold on to the data of the key this object held before. It is
         * disposed of once the new key data has been copied in, as the caller
         * may be decoding out of it. */
        prevData = pkey->pkey.ptr;
        prevSz = pkey->pkey_sz;
        pkey->pkey.ptr = NULL;
        pkey->pkey_sz = 0;
    #ifdef OPENSSL_EXTRA
        /* Dispose of the key object of the key this object held before. The
         * type is about to change and wolfSSL_EVP_PKEY_free() only disposes of
         * the object matching the type set. */
        clearEVPPkeyKeys(pkey);
    #endif
        /* Drop metadata describing the key this object held before, so a
         * reused object decodes to the same state as a new one. A failure
         * below must not leave the object advertising the old type. */
        pkey->type = WC_EVP_PKEY_NONE;
        pkey->pkcs8HeaderSz = 0;
        pkey->save_type = 0;
    #ifdef HAVE_ECC
        pkey->pkey_curve = 0;
    #endif
    #ifdef WOLFSSL_HAVE_MLDSA
        WOLFSSL_ATOMIC_STORE(pkey->mldsaOID, 0);
    #endif
    }
    else {
        pkey = wolfSSL_EVP_PKEY_new();
        if (pkey == NULL) {
            WOLFSSL_MSG("wolfSSL_EVP_PKEY_new error");
            return 0;
        }
    }

    /* Set the size and allocate memory for key data to be copied into.
     * Heap hint and DYNAMIC_TYPE must match the frees of pkey.ptr. */
    pkey->pkey_sz = (int)memSz;
    if (memSz > 0) {
        pkey->pkey.ptr = (char*)XMALLOC((size_t)memSz, pkey->heap,
            DYNAMIC_TYPE_PUBLIC_KEY);
        if (pkey->pkey.ptr == NULL) {
            /* No encoding held - do not describe one. */
            pkey->pkey_sz = 0;
            ret = 0;
        }
        if (ret == 1) {
            /* Copy in key data. */
            XMEMCPY(pkey->pkey.ptr, mem, memSz);
        }
    }
    /* The data of the key held before is no longer referenced. */
    if (prevData != NULL) {
        if (prevSz > 0) {
            ForceZero(prevData, (word32)prevSz);
        }
        XFREE(prevData, pkey->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    }
    if (ret == 1) {
        /* Set key type passed in and return object. */
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
 * @return  0 when input was recognized as this key type but
 *            object creation/import failed.
 * @return  WOLFSSL_FATAL_ERROR when input is not this key type.
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
 * @return  0 when input was recognized as this key type but
 *            object creation/import failed.
 * @return  WOLFSSL_FATAL_ERROR when input is not this key type.
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

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
/**
 * Try to make an Ed25519 EVP PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @param [in]      prePopulated  1 means *out already holds the input bytes
 *                         so the d2i_make_pkey allocate/copy is skipped.
 * @return  1 on success.
 * @return  0 when input was recognized as this key type but object
 *            creation/import failed.
 * @return  WOLFSSL_FATAL_ERROR when input is not this key type.
 */
static int d2iTryEd25519Key(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv, int prePopulated)
{
    ed25519_key* edKey = NULL;
    word32 keyIdx = 0;
    int isEdKey;
    int ret = 1;
    void* heap = NULL;

    if (*out != NULL) {
        heap = (*out)->heap;
    }

    edKey = wolfSSL_ED25519_new(heap, INVALID_DEVID);
    if (edKey == NULL) {
        return 0;
    }

    /* Decode data as an Ed25519 key in DER form (SubjectPublicKeyInfo for
     * public keys, PKCS#8 PrivateKeyInfo for private keys). */
    if (priv) {
        isEdKey = (wc_Ed25519PrivateKeyDecode(mem, &keyIdx, edKey,
            (word32)memSz) == 0);
    }
    else {
        isEdKey = (wc_Ed25519PublicKeyDecode(mem, &keyIdx, edKey,
            (word32)memSz) == 0);
    }

    if (!isEdKey) {
        wolfSSL_ED25519_free(edKey);
        return WOLFSSL_FATAL_ERROR;
    }

#ifdef HAVE_ED25519_MAKE_KEY
    /* A PKCS#8 v1 PrivateKeyInfo carries only the private seed, so the
     * decoded key has no public part.  Derive it (deterministic from the
     * seed; wc_ed25519_make_public also stores it in the key) so the
     * resulting EVP_PKEY is complete and callers can later export/embed the
     * public key.  Best-effort: on failure the key is left private-only. */
    if (priv && !edKey->pubKeySet) {
        byte pub[ED25519_PUB_KEY_SIZE];

        if (wc_ed25519_make_public(edKey, pub, sizeof(pub)) != 0) {
            WOLFSSL_MSG("wc_ed25519_make_public failed; "
                        "EVP_PKEY has no public part");
        }
    }
#endif /* HAVE_ED25519_MAKE_KEY */

    /* Copy the consumed DER into pkey->pkey.ptr, unless the caller
     * pre-filled the EVP PKEY with the input bytes (d2i_evp_pkey()).
     * A reused key must be re-populated here. */
    if (!prePopulated) {
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_ED25519);
    }
    if (ret == 1) {
        (*out)->ownEd25519 = 1;
        (*out)->ed25519 = edKey;
    }
    else {
        wolfSSL_ED25519_free(edKey);
    }

    return ret;
}
#endif /* HAVE_ED25519i && HAVE_ED25519_KEY_IMPORT */

#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
/**
 * Try to make an Ed448 EVP PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @param [in]      prePopulated  1 means *out already holds the input bytes
 *                         so the d2i_make_pkey allocate/copy is skipped.
 * @return  1 on success.
 * @return  0 when input was recognized as this key type but object
 *            creation/import failed.
 * @return  WOLFSSL_FATAL_ERROR when input is not this key type.
 */
static int d2iTryEd448Key(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv, int prePopulated)
{
    ed448_key* edKey = NULL;
    word32 keyIdx = 0;
    int isEdKey;
    int ret = 1;
    void* heap = NULL;

    if (*out != NULL) {
        heap = (*out)->heap;
    }

    edKey = wolfSSL_ED448_new(heap, INVALID_DEVID);
    if (edKey == NULL) {
        return 0;
    }

    /* Decode data as an Ed448 key in DER form (SubjectPublicKeyInfo for
     * public keys, PKCS#8 PrivateKeyInfo for private keys). */
    if (priv) {
        isEdKey = (wc_Ed448PrivateKeyDecode(mem, &keyIdx, edKey,
            (word32)memSz) == 0);
    }
    else {
        isEdKey = (wc_Ed448PublicKeyDecode(mem, &keyIdx, edKey,
            (word32)memSz) == 0);
    }

    if (!isEdKey) {
        wolfSSL_ED448_free(edKey);
        return WOLFSSL_FATAL_ERROR;
    }

    /* Copy the consumed DER into pkey->pkey.ptr, unless the caller
     * pre-filled the EVP PKEY with the input bytes (d2i_evp_pkey()).
     * A reused key must be re-populated here. */
    if (!prePopulated) {
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_ED448);
    }
    if (ret == 1) {
        (*out)->ownEd448 = 1;
        (*out)->ed448 = edKey;
    }
    else {
        wolfSSL_ED448_free(edKey);
    }

    return ret;
}
#endif /* HAVE_ED448 */

#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
/**
 * Try to make an X25519 EVP PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @param [in]      prePopulated  1 means *out already holds the input bytes
 *                         so the d2i_make_pkey allocate/copy is skipped.
 * @return  1 on success.
 * @return  0 when input was recognized as this key type but object
 *            creation/import failed.
 * @return  WOLFSSL_FATAL_ERROR when input is not this key type.
 */
static int d2iTryX25519Key(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv, int prePopulated)
{
    curve25519_key* cKey = NULL;
    word32 keyIdx = 0;
    int isCurveKey;
    int ret = 1;
    void* heap = NULL;

    if (*out != NULL) {
        heap = (*out)->heap;
    }

    cKey = (curve25519_key*)XMALLOC(sizeof(curve25519_key), heap,
        DYNAMIC_TYPE_CURVE25519);
    if (cKey == NULL) {
        return 0;
    }
    if (wc_curve25519_init_ex(cKey, heap, INVALID_DEVID) != 0) {
        XFREE(cKey, heap, DYNAMIC_TYPE_CURVE25519);
        return 0;
    }

    /* Decode data as an X25519 key in DER form (SubjectPublicKeyInfo for
     * public keys, PKCS#8 PrivateKeyInfo for private keys).
     *
     * The value is imported here rather than left to
     * wc_Curve25519PrivateKeyDecode(), which takes the scalar big-endian to
     * match the encoder beside it.  RFC 8410 carries the little-endian value
     * of RFC 7748, as OpenSSL reads and writes it, and a big-endian import
     * would also clamp the wrong end of it.  The decode hands back where the
     * key actually sits: an RFC 5958 v2 key carries the public key after the
     * private one, so the position cannot be assumed from the length. */
    if (priv) {
        const byte* privKey = NULL;
        const byte* pubKey = NULL;
        word32 privKeyLen = 0;
        word32 pubKeyLen = 0;
        int keyType = X25519k;

        /* The public key outputs are required even though only the private
         * key is wanted: a v2 OneAsymmetricKey carries a public key too, and
         * the decode refuses to run with nowhere to report it. */
        isCurveKey = (DecodeAsymKey_Assign(mem, &keyIdx, (word32)memSz, NULL,
            NULL, &privKey, &privKeyLen, &pubKey, &pubKeyLen, &keyType) == 0);
        if (isCurveKey && (privKeyLen == CURVE25519_KEYSIZE)) {
            isCurveKey = (wc_curve25519_import_private_ex(privKey, privKeyLen,
                cKey, EC25519_LITTLE_ENDIAN) == 0);
        }
        else {
            isCurveKey = 0;
        }
    }
    else {
        const byte* pubKey = NULL;
        word32 pubKeyLen = 0;
        int keyType = X25519k;

        isCurveKey = (DecodeAsymKeyPublic_Assign(mem, &keyIdx, (word32)memSz,
            &pubKey, &pubKeyLen, &keyType) == 0);
        if (isCurveKey && (pubKeyLen == CURVE25519_KEYSIZE)) {
            isCurveKey = (wc_curve25519_import_public_ex(pubKey, pubKeyLen,
                cKey, EC25519_LITTLE_ENDIAN) == 0);
        }
        else {
            isCurveKey = 0;
        }
    }

    if (!isCurveKey) {
        wc_curve25519_free(cKey);
        XFREE(cKey, heap, DYNAMIC_TYPE_CURVE25519);
        return WOLFSSL_FATAL_ERROR;
    }

    /* Copy the consumed DER into pkey->pkey.ptr, unless the caller
     * pre-filled the EVP PKEY with the input bytes (d2i_evp_pkey()). */
    if (!prePopulated) {
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_X25519);
    }
    if (ret == 1) {
        (*out)->ownCurve25519 = 1;
        (*out)->curve25519 = cKey;
    }
    else {
        wc_curve25519_free(cKey);
        XFREE(cKey, heap, DYNAMIC_TYPE_CURVE25519);
    }

    return ret;
}
#endif /* HAVE_CURVE25519 && HAVE_CURVE25519_KEY_IMPORT */

#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT)
/**
 * Try to make an X448 EVP PKEY from data.
 *
 * See d2iTryX25519Key() for the parameters and return values.
 */
static int d2iTryX448Key(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv, int prePopulated)
{
    curve448_key* cKey = NULL;
    word32 keyIdx = 0;
    int isCurveKey;
    int ret = 1;
    void* heap = NULL;

    if (*out != NULL) {
        heap = (*out)->heap;
    }

    cKey = (curve448_key*)XMALLOC(sizeof(curve448_key), heap,
        DYNAMIC_TYPE_CURVE448);
    if (cKey == NULL) {
        return 0;
    }
    if (wc_curve448_init(cKey) != 0) {
        XFREE(cKey, heap, DYNAMIC_TYPE_CURVE448);
        return 0;
    }

    /* Decode data as an X448 key in DER form (SubjectPublicKeyInfo for public
     * keys, PKCS#8 PrivateKeyInfo for private keys).  See d2iTryX25519Key()
     * for why the value is imported here, with an explicit endianness, from
     * where the decode says the key sits. */
    if (priv) {
        const byte* privKey = NULL;
        const byte* pubKey = NULL;
        word32 privKeyLen = 0;
        word32 pubKeyLen = 0;
        int keyType = X448k;

        /* See d2iTryX25519Key() for why the public key outputs are given. */
        isCurveKey = (DecodeAsymKey_Assign(mem, &keyIdx, (word32)memSz, NULL,
            NULL, &privKey, &privKeyLen, &pubKey, &pubKeyLen, &keyType) == 0);
        if (isCurveKey && (privKeyLen == CURVE448_KEY_SIZE)) {
            isCurveKey = (wc_curve448_import_private_ex(privKey, privKeyLen,
                cKey, EC448_LITTLE_ENDIAN) == 0);
        }
        else {
            isCurveKey = 0;
        }
    }
    else {
        const byte* pubKey = NULL;
        word32 pubKeyLen = 0;
        int keyType = X448k;

        isCurveKey = (DecodeAsymKeyPublic_Assign(mem, &keyIdx, (word32)memSz,
            &pubKey, &pubKeyLen, &keyType) == 0);
        if (isCurveKey && (pubKeyLen == CURVE448_KEY_SIZE)) {
            isCurveKey = (wc_curve448_import_public_ex(pubKey, pubKeyLen,
                cKey, EC448_LITTLE_ENDIAN) == 0);
        }
        else {
            isCurveKey = 0;
        }
    }

    if (!isCurveKey) {
        wc_curve448_free(cKey);
        XFREE(cKey, heap, DYNAMIC_TYPE_CURVE448);
        return WOLFSSL_FATAL_ERROR;
    }

    if (!prePopulated) {
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_X448);
    }
    if (ret == 1) {
        (*out)->ownCurve448 = 1;
        (*out)->curve448 = cKey;
    }
    else {
        wc_curve448_free(cKey);
        XFREE(cKey, heap, DYNAMIC_TYPE_CURVE448);
    }

    return ret;
}
#endif /* HAVE_CURVE448 && HAVE_CURVE448_KEY_IMPORT */

/* Create a new EVP_PKEY from raw Ed25519 or Ed448 key material.
 *
 * Used for for callers who already have the raw key bytes and shouldn't need
 * to rewrap them in an SPKI just to decode.
 *
 * @param [in] type  WC_EVP_PKEY_ED25519 or WC_EVP_PKEY_ED448.
 * @param [in] e     Engine. Ignored; accepted for OpenSSL API parity.
 * @param [in] pub   Raw public key bytes.
 * @param [in] len   Length of pub. Must match the curve's public key size
 *                   (ED25519_PUB_KEY_SIZE or ED448_PUB_KEY_SIZE).
 * @return  WOLFSSL_EVP_PKEY on success, NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_EVP_PKEY_new_raw_public_key(int type,
    WOLFSSL_ENGINE* e, const unsigned char* pub, size_t len)
{
    WOLFSSL_EVP_PKEY* pkey;
    int ok = 0;

    (void)e;
    WOLFSSL_ENTER("wolfSSL_EVP_PKEY_new_raw_public_key");

    if (pub == NULL || len == 0) {
        return NULL;
    }

    pkey = wolfSSL_EVP_PKEY_new();
    if (pkey == NULL) {
        return NULL;
    }

    switch (type) {
    #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
        case WC_EVP_PKEY_ED25519: {
            ed25519_key* edKey;
            if (len != ED25519_PUB_KEY_SIZE) {
                break;
            }
            edKey = wolfSSL_ED25519_new(pkey->heap, INVALID_DEVID);
            if (edKey == NULL) {
                break;
            }
            if (wc_ed25519_import_public(pub, (word32)len, edKey) != 0) {
                wolfSSL_ED25519_free(edKey);
                break;
            }
            pkey->type       = WC_EVP_PKEY_ED25519;
            pkey->ed25519    = edKey;
            pkey->ownEd25519 = 1;
            ok = 1;
            break;
        }
    #endif
    #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
        case WC_EVP_PKEY_ED448: {
            ed448_key* edKey;
            if (len != ED448_PUB_KEY_SIZE) {
                break;
            }
            edKey = wolfSSL_ED448_new(pkey->heap, INVALID_DEVID);
            if (edKey == NULL) {
                break;
            }
            if (wc_ed448_import_public(pub, (word32)len, edKey) != 0) {
                wolfSSL_ED448_free(edKey);
                break;
            }
            pkey->type     = WC_EVP_PKEY_ED448;
            pkey->ed448    = edKey;
            pkey->ownEd448 = 1;
            ok = 1;
            break;
        }
    #endif
    #ifdef HAVE_CURVE25519
        case WC_EVP_PKEY_X25519: {
            curve25519_key* cKey;
            if (len != CURVE25519_PUB_KEY_SIZE) {
                break;
            }
            cKey = (curve25519_key*)XMALLOC(sizeof(curve25519_key), pkey->heap,
                DYNAMIC_TYPE_CURVE25519);
            if (cKey == NULL) {
                break;
            }
            if (wc_curve25519_init_ex(cKey, pkey->heap, INVALID_DEVID) != 0) {
                XFREE(cKey, pkey->heap, DYNAMIC_TYPE_CURVE25519);
                break;
            }
            /* Raw X25519 keys are little-endian (RFC 7748). */
            if (wc_curve25519_import_public_ex(pub, (word32)len, cKey,
                    EC25519_LITTLE_ENDIAN) != 0) {
                wc_curve25519_free(cKey);
                XFREE(cKey, pkey->heap, DYNAMIC_TYPE_CURVE25519);
                break;
            }
            pkey->type          = WC_EVP_PKEY_X25519;
            pkey->curve25519    = cKey;
            pkey->ownCurve25519 = 1;
            ok = 1;
            break;
        }
    #endif
    #ifdef HAVE_CURVE448
        case WC_EVP_PKEY_X448: {
            curve448_key* cKey;
            if (len != CURVE448_PUB_KEY_SIZE) {
                break;
            }
            cKey = (curve448_key*)XMALLOC(sizeof(curve448_key), pkey->heap,
                DYNAMIC_TYPE_CURVE448);
            if (cKey == NULL) {
                break;
            }
            if (wc_curve448_init_ex(cKey, pkey->heap, INVALID_DEVID) != 0) {
                XFREE(cKey, pkey->heap, DYNAMIC_TYPE_CURVE448);
                break;
            }
            /* Raw X448 keys are little-endian (RFC 7748). */
            if (wc_curve448_import_public_ex(pub, (word32)len, cKey,
                    EC448_LITTLE_ENDIAN) != 0) {
                wc_curve448_free(cKey);
                XFREE(cKey, pkey->heap, DYNAMIC_TYPE_CURVE448);
                break;
            }
            pkey->type        = WC_EVP_PKEY_X448;
            pkey->curve448    = cKey;
            pkey->ownCurve448 = 1;
            ok = 1;
            break;
        }
    #endif
        default:
            break;
    }

    if (!ok) {
        wolfSSL_EVP_PKEY_free(pkey);
        return NULL;
    }

    /* Stash the raw bytes so callers that later serialize the EVP_PKEY see
     * consistent state. */
    pkey->pkey.ptr = (char*)XMALLOC(len, pkey->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (pkey->pkey.ptr == NULL) {
        wolfSSL_EVP_PKEY_free(pkey);
        return NULL;
    }
    XMEMCPY(pkey->pkey.ptr, pub, len);
    pkey->pkey_sz = (int)len;

    return pkey;
}

/* Private-key counterpart to wolfSSL_EVP_PKEY_new_raw_public_key. The raw
 * input is the 32-byte seed (Ed25519) or 57-byte seed (Ed448).
 */
/* Raw key forms exist only for the curves below; without any of them the
 * getters have nothing to report. */
#if (defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)) || \
    (defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)) || \
    (defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_EXPORT)) || \
    (defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_EXPORT))
    #define WOLFSSL_EVP_HAVE_RAW_KEYS
#endif

#ifdef WOLFSSL_EVP_HAVE_RAW_KEYS
/* Copy a raw key out to the caller's buffer, honouring OpenSSL's
 * query-then-fetch protocol.
 *
 * out/outLen - when out is NULL, *outLen receives the size needed and nothing
 *              is copied.  Otherwise *outLen is the buffer size on entry and
 *              the size written on exit.
 *
 * Returns 1 on success, 0 when the buffer is too small.
 */
static int wolfssl_evp_pkey_raw_out(const byte* raw, word32 rawLen,
    unsigned char* out, size_t* outLen)
{
    if (out == NULL) {
        *outLen = (size_t)rawLen;
        return 1;
    }
    if (*outLen < (size_t)rawLen) {
        WOLFSSL_MSG("buffer too small for raw key");
        *outLen = (size_t)rawLen;
        return 0;
    }
    XMEMCPY(out, raw, rawLen);
    *outLen = (size_t)rawLen;
    return 1;
}
#endif /* WOLFSSL_EVP_HAVE_RAW_KEYS */

#ifdef WOLFSSL_EVP_HAVE_RAW_KEYS
/* Decide whether pkey->pkey.ptr holds the raw private key.
 *
 * That field is the key's DER for anything decoded from a file or a buffer,
 * and only wolfSSL_EVP_PKEY_new_raw_private_key() puts raw bytes there.  The
 * two are told apart by size: a raw private key is exactly as long as the one
 * the wolfCrypt key exports, while a DER encoding never is.
 *
 * The cache matters because wolfCrypt clamps an X25519/X448 scalar on import
 * (RFC 7748), so re-exporting one would not give back what the caller set,
 * while OpenSSL hands back exactly what it was given.
 */
static int wolfssl_evp_pkey_raw_cached(const WOLFSSL_EVP_PKEY* pkey,
    word32 rawLen)
{
    return (pkey->pkey.ptr != NULL) && (pkey->pkey_sz > 0) &&
           ((word32)pkey->pkey_sz == rawLen);
}
#endif /* WOLFSSL_EVP_HAVE_RAW_KEYS */

int wolfSSL_EVP_PKEY_get_raw_private_key(const WOLFSSL_EVP_PKEY* pkey,
    unsigned char* priv, size_t* len)
{
#ifdef WOLFSSL_EVP_HAVE_RAW_KEYS
    int ret = 0;
    byte buf[128];
    word32 bufLen = (word32)sizeof(buf);
#endif

    WOLFSSL_ENTER("wolfSSL_EVP_PKEY_get_raw_private_key");

    if (pkey == NULL || len == NULL) {
        return 0;
    }

#ifndef WOLFSSL_EVP_HAVE_RAW_KEYS
    (void)priv;
    WOLFSSL_MSG("build has no key type with a raw form");
    return 0;
#else

    switch (pkey->type) {
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
        case WC_EVP_PKEY_ED25519:
            if (pkey->ed25519 == NULL) {
                break;
            }
            if (wc_ed25519_export_private_only(pkey->ed25519, buf, &bufLen)
                    != 0) {
                WOLFSSL_MSG("wc_ed25519_export_private_only failed");
                break;
            }
            if (wolfssl_evp_pkey_raw_cached(pkey, bufLen)) {
                ret = wolfssl_evp_pkey_raw_out((const byte*)pkey->pkey.ptr,
                    bufLen, priv, len);
            }
            else {
                ret = wolfssl_evp_pkey_raw_out(buf, bufLen, priv, len);
            }
            break;
#endif
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)
        case WC_EVP_PKEY_ED448:
            if (pkey->ed448 == NULL) {
                break;
            }
            if (wc_ed448_export_private_only(pkey->ed448, buf, &bufLen) != 0) {
                WOLFSSL_MSG("wc_ed448_export_private_only failed");
                break;
            }
            if (wolfssl_evp_pkey_raw_cached(pkey, bufLen)) {
                ret = wolfssl_evp_pkey_raw_out((const byte*)pkey->pkey.ptr,
                    bufLen, priv, len);
            }
            else {
                ret = wolfssl_evp_pkey_raw_out(buf, bufLen, priv, len);
            }
            break;
#endif
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_EXPORT)
        case WC_EVP_PKEY_X25519:
            if (pkey->curve25519 == NULL) {
                break;
            }
            /* Raw X25519 keys are little-endian (RFC 7748). */
            if (wc_curve25519_export_private_raw_ex(pkey->curve25519, buf,
                    &bufLen, EC25519_LITTLE_ENDIAN) != 0) {
                WOLFSSL_MSG("wc_curve25519_export_private_raw_ex failed");
                break;
            }
            if (wolfssl_evp_pkey_raw_cached(pkey, bufLen)) {
                ret = wolfssl_evp_pkey_raw_out((const byte*)pkey->pkey.ptr,
                    bufLen, priv, len);
            }
            else {
                ret = wolfssl_evp_pkey_raw_out(buf, bufLen, priv, len);
            }
            break;
#endif
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_EXPORT)
        case WC_EVP_PKEY_X448:
            if (pkey->curve448 == NULL) {
                break;
            }
            if (wc_curve448_export_private_raw_ex(pkey->curve448, buf, &bufLen,
                    EC448_LITTLE_ENDIAN) != 0) {
                WOLFSSL_MSG("wc_curve448_export_private_raw_ex failed");
                break;
            }
            if (wolfssl_evp_pkey_raw_cached(pkey, bufLen)) {
                ret = wolfssl_evp_pkey_raw_out((const byte*)pkey->pkey.ptr,
                    bufLen, priv, len);
            }
            else {
                ret = wolfssl_evp_pkey_raw_out(buf, bufLen, priv, len);
            }
            break;
#endif
        default:
            WOLFSSL_MSG("key type has no raw private form");
            break;
    }

    ForceZero(buf, sizeof(buf));

    return ret;
#endif /* WOLFSSL_EVP_HAVE_RAW_KEYS */
}

/* Get the raw public key of a key type that has one.
 *
 * See wolfSSL_EVP_PKEY_get_raw_private_key() on where the bytes come from.
 *
 * Returns 1 on success, 0 otherwise.
 */
int wolfSSL_EVP_PKEY_get_raw_public_key(const WOLFSSL_EVP_PKEY* pkey,
    unsigned char* pub, size_t* len)
{
#ifdef WOLFSSL_EVP_HAVE_RAW_KEYS
    int ret = 0;
    byte buf[128];
    word32 bufLen = (word32)sizeof(buf);
#endif

    WOLFSSL_ENTER("wolfSSL_EVP_PKEY_get_raw_public_key");

    if (pkey == NULL || len == NULL) {
        return 0;
    }

#ifndef WOLFSSL_EVP_HAVE_RAW_KEYS
    (void)pub;
    WOLFSSL_MSG("build has no key type with a raw form");
    return 0;
#else

    switch (pkey->type) {
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
        case WC_EVP_PKEY_ED25519:
            if (pkey->ed25519 == NULL) {
                break;
            }
            /* Derive whenever a private key is present, rather than asking
             * whether a public key is already held. wc_ed25519_make_public()
             * writes the public key into the buffer it is given and sets
             * pubKeySet, but never stores the key on the key itself, so after
             * one call the flag claims a public key that is not there and
             * exporting would hand back zeros. It also wants exactly the
             * public key size, not the capacity of the buffer. */
            if (pkey->ed25519->privKeySet) {
                if (wc_ed25519_make_public(pkey->ed25519, buf,
                        ED25519_PUB_KEY_SIZE) != 0) {
                    WOLFSSL_MSG("wc_ed25519_make_public failed");
                    break;
                }
                bufLen = ED25519_PUB_KEY_SIZE;
            }
            else {
                bufLen = (word32)sizeof(buf);
                if (wc_ed25519_export_public(pkey->ed25519, buf, &bufLen)
                        != 0) {
                    WOLFSSL_MSG("wc_ed25519_export_public failed");
                    break;
                }
            }
            ret = wolfssl_evp_pkey_raw_out(buf, bufLen, pub, len);
            break;
#endif
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)
        case WC_EVP_PKEY_ED448:
            if (pkey->ed448 == NULL) {
                break;
            }
            /* See the Ed25519 case: make_public() fills the buffer and sets
             * pubKeySet without storing the public key on the key itself. */
            if (pkey->ed448->privKeySet) {
                if (wc_ed448_make_public(pkey->ed448, buf,
                        ED448_PUB_KEY_SIZE) != 0) {
                    WOLFSSL_MSG("wc_ed448_make_public failed");
                    break;
                }
                bufLen = ED448_PUB_KEY_SIZE;
            }
            else {
                bufLen = (word32)sizeof(buf);
                if (wc_ed448_export_public(pkey->ed448, buf, &bufLen) != 0) {
                    WOLFSSL_MSG("wc_ed448_export_public failed");
                    break;
                }
            }
            ret = wolfssl_evp_pkey_raw_out(buf, bufLen, pub, len);
            break;
#endif
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_EXPORT)
        case WC_EVP_PKEY_X25519:
            if (pkey->curve25519 == NULL) {
                break;
            }
            if (wc_curve25519_export_public_ex(pkey->curve25519, buf, &bufLen,
                    EC25519_LITTLE_ENDIAN) != 0) {
                WOLFSSL_MSG("wc_curve25519_export_public_ex failed");
                break;
            }
            ret = wolfssl_evp_pkey_raw_out(buf, bufLen, pub, len);
            break;
#endif
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_EXPORT)
        case WC_EVP_PKEY_X448:
            if (pkey->curve448 == NULL) {
                break;
            }
            if (wc_curve448_export_public_ex(pkey->curve448, buf, &bufLen,
                    EC448_LITTLE_ENDIAN) != 0) {
                WOLFSSL_MSG("wc_curve448_export_public_ex failed");
                break;
            }
            ret = wolfssl_evp_pkey_raw_out(buf, bufLen, pub, len);
            break;
#endif
        default:
            WOLFSSL_MSG("key type has no raw public form");
            break;
    }

    return ret;
#endif /* WOLFSSL_EVP_HAVE_RAW_KEYS */
}

WOLFSSL_EVP_PKEY* wolfSSL_EVP_PKEY_new_raw_private_key(int type,
    WOLFSSL_ENGINE* e, const unsigned char* priv, size_t len)
{
    WOLFSSL_EVP_PKEY* pkey;
    int ok = 0;

    (void)e;
    WOLFSSL_ENTER("wolfSSL_EVP_PKEY_new_raw_private_key");

    if (priv == NULL || len == 0) {
        return NULL;
    }

    pkey = wolfSSL_EVP_PKEY_new();
    if (pkey == NULL) {
        return NULL;
    }

    switch (type) {
    #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
        case WC_EVP_PKEY_ED25519: {
            ed25519_key* edKey;
        #ifdef HAVE_ED25519_MAKE_KEY
            byte edPub[ED25519_PUB_KEY_SIZE];
        #endif
            if (len != ED25519_KEY_SIZE) {
                break;
            }
            edKey = wolfSSL_ED25519_new(pkey->heap, INVALID_DEVID);
            if (edKey == NULL) {
                break;
            }
            if (wc_ed25519_import_private_only(priv, (word32)len, edKey)
                    != 0) {
                wolfSSL_ED25519_free(edKey);
                break;
            }
        #ifdef HAVE_ED25519_MAKE_KEY
            /* The raw input is the seed alone, so the imported key has no
             * public half.  Derive it (wc_ed25519_make_public stores it in the
             * key) so a key built this way is interchangeable with one decoded
             * from PKCS#8: i2d_PUBKEY, EVP_PKEY_cmp and signing all need it. */
            if (wc_ed25519_make_public(edKey, edPub, sizeof(edPub)) != 0) {
                wolfSSL_ED25519_free(edKey);
                break;
            }
        #endif
            pkey->type       = WC_EVP_PKEY_ED25519;
            pkey->ed25519    = edKey;
            pkey->ownEd25519 = 1;
            ok = 1;
            break;
        }
    #endif
    #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
        case WC_EVP_PKEY_ED448: {
            ed448_key* edKey;
            if (len != ED448_KEY_SIZE) {
                break;
            }
            edKey = wolfSSL_ED448_new(pkey->heap, INVALID_DEVID);
            if (edKey == NULL) {
                break;
            }
            if (wc_ed448_import_private_only(priv, (word32)len, edKey) != 0) {
                wolfSSL_ED448_free(edKey);
                break;
            }
            pkey->type     = WC_EVP_PKEY_ED448;
            pkey->ed448    = edKey;
            pkey->ownEd448 = 1;
            ok = 1;
            break;
        }
    #endif
    #ifdef HAVE_CURVE25519
        case WC_EVP_PKEY_X25519: {
            curve25519_key* cKey;
            if (len != CURVE25519_KEYSIZE) {
                break;
            }
            cKey = (curve25519_key*)XMALLOC(sizeof(curve25519_key), pkey->heap,
                DYNAMIC_TYPE_CURVE25519);
            if (cKey == NULL) {
                break;
            }
            if (wc_curve25519_init_ex(cKey, pkey->heap, INVALID_DEVID) != 0) {
                XFREE(cKey, pkey->heap, DYNAMIC_TYPE_CURVE25519);
                break;
            }
        #ifdef WOLFSSL_CURVE25519_BLINDING
            /* Use the EVP_PKEY's RNG for scalar blinding on shared-secret. */
            (void)wc_curve25519_set_rng(cKey, &pkey->rng);
        #endif
            /* Raw X25519 keys are little-endian (RFC 7748). */
            if (wc_curve25519_import_private_ex(priv, (word32)len, cKey,
                    EC25519_LITTLE_ENDIAN) != 0) {
                wc_curve25519_free(cKey);
                XFREE(cKey, pkey->heap, DYNAMIC_TYPE_CURVE25519);
                break;
            }
            pkey->type          = WC_EVP_PKEY_X25519;
            pkey->curve25519    = cKey;
            pkey->ownCurve25519 = 1;
            ok = 1;
            break;
        }
    #endif
    #ifdef HAVE_CURVE448
        case WC_EVP_PKEY_X448: {
            curve448_key* cKey;
            if (len != CURVE448_KEY_SIZE) {
                break;
            }
            cKey = (curve448_key*)XMALLOC(sizeof(curve448_key), pkey->heap,
                DYNAMIC_TYPE_CURVE448);
            if (cKey == NULL) {
                break;
            }
            if (wc_curve448_init_ex(cKey, pkey->heap, INVALID_DEVID) != 0) {
                XFREE(cKey, pkey->heap, DYNAMIC_TYPE_CURVE448);
                break;
            }
            /* Raw X448 keys are little-endian (RFC 7748). */
            if (wc_curve448_import_private_ex(priv, (word32)len, cKey,
                    EC448_LITTLE_ENDIAN) != 0) {
                wc_curve448_free(cKey);
                XFREE(cKey, pkey->heap, DYNAMIC_TYPE_CURVE448);
                break;
            }
            pkey->type        = WC_EVP_PKEY_X448;
            pkey->curve448    = cKey;
            pkey->ownCurve448 = 1;
            ok = 1;
            break;
        }
    #endif
        default:
            break;
    }

    if (!ok) {
        wolfSSL_EVP_PKEY_free(pkey);
        return NULL;
    }

    pkey->pkey.ptr = (char*)XMALLOC(len, pkey->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (pkey->pkey.ptr == NULL) {
        wolfSSL_EVP_PKEY_free(pkey);
        return NULL;
    }
    XMEMCPY(pkey->pkey.ptr, priv, len);
    pkey->pkey_sz = (int)len;

    return pkey;
}

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
 * @return  0 when input was recognized as this key type but
 *            object creation/import failed.
 * @return  WOLFSSL_FATAL_ERROR when input is not this key type.
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
 * @return  0 when input was recognized as this key type but
 *            object creation/import failed.
 * @return  WOLFSSL_FATAL_ERROR when input is not this key type.
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
 * @return  0 when input was recognized as this key type but
 *            object creation/import failed.
 * @return  WOLFSSL_FATAL_ERROR when input is not this key type.
 */
static int d2iTryAltDhKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv)
{
    WOLFSSL_DH* dhObj = NULL;
    word32  keyIdx = 0;
    DhKey*  key = NULL;
    int elements;
    int ret = 1;

    /* Create DH key object from data. */
    dhObj = wolfSSL_DH_new();
    if (dhObj == NULL) {
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 1) {
        key = (DhKey*)dhObj->internal;
        /* Try decoding data as a DH public key. */
        if (wc_DhKeyDecode(mem, &keyIdx, key, (word32)memSz) != 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 1) {
        /* DH key has data and is external to DH object. */
        elements = ELEMENT_P | ELEMENT_G | ELEMENT_Q | ELEMENT_PUB;
        if (priv) {
            elements |= ELEMENT_PRV;
        }
        if (SetDhExternal_ex(dhObj, elements) != WOLFSSL_SUCCESS) {
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Create an EVP PKEY object. */
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_DH);
    }
    if (ret == 1) {
        /* Put DH key object into EVP PKEY object. */
        (*out)->ownDh = 1;
        (*out)->dh = dhObj;
    }
    else if (dhObj != NULL) {
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
    word32 idx = 0;
    return (wc_falcon_set_level(falcon, level) == 0) &&
           (wc_Falcon_PrivateKeyDecode(mem, &idx, falcon,
                                        (word32)memSz) == 0);
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
 * @return  0 when input was recognized as this key type but
 *            object creation/import failed.
 * @return  WOLFSSL_FATAL_ERROR when input is not this key type.
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

#ifdef WOLFSSL_HAVE_MLDSA
/**
 * Try to make an ML-DSA EVP PKEY from data.
 *
 * Accepts either raw key bytes or DER (PKCS#8 / SPKI). Raw bytes are
 * size-keyed, so each level is tried in turn. DER input is decoded once,
 * letting the decoder auto-detect the level from the OID.
 *
 * Under WOLFSSL_MLDSA_NO_ASN1 there is no PKCS#8 decoder, so a DER private
 * key is always treated as not this key type; only raw bytes are accepted.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @param [in]      prePopulated  1 means *out already holds the input bytes
 *                         so the d2i_make_pkey allocate/copy is skipped.
 * @param [in]      allowRaw  1 means size-keyed raw key bytes are accepted
 *                         in addition to DER (auto-detect path only).
 * @return  1 on success.
 * @return  0 when input was recognized as this key type but
 *            object creation/import failed.
 * @return  WOLFSSL_FATAL_ERROR when input is not this key type.
 */
static int d2iTryMlDsaKey(WOLFSSL_EVP_PKEY** out, const unsigned char* mem,
    long memSz, int priv, int prePopulated, int allowRaw)
{
    static const byte levels[] = { WC_ML_DSA_44, WC_ML_DSA_65, WC_ML_DSA_87 };
    word32 inSz = (word32)memSz;
    word32 keyIdx = 0;
    int isMlDsa = 0;
    int i, numLevels, rc;
    int oidSum = 0;
    int ret;
    WC_DECLARE_VAR(mldsa, wc_MlDsaKey, 1, NULL);

#if !defined(WOLFSSL_MLDSA_PRIVATE_KEY)
    if (priv) {
        return WOLFSSL_FATAL_ERROR;
    }
#endif

    WC_ALLOC_VAR_EX(mldsa, wc_MlDsaKey, 1, NULL, DYNAMIC_TYPE_MLDSA,
        return 0);

    if (wc_MlDsaKey_Init(mldsa, NULL, INVALID_DEVID) != 0) {
        WC_FREE_VAR_EX(mldsa, NULL, DYNAMIC_TYPE_MLDSA);
        return 0;
    }

    /* Raw key bytes are size-keyed, try each level. Only the auto-detect
     * path accepts raw bytes; the typed d2i entry points are DER APIs. */
    numLevels = allowRaw ? (int)(sizeof(levels) / sizeof(levels[0])) : 0;
    for (i = 0; i < numLevels && !isMlDsa; i++) {
        if (wc_MlDsaKey_SetParams(mldsa, levels[i]) != 0) {
            continue;
        }
    #if defined(WOLFSSL_MLDSA_PRIVATE_KEY)
        if (priv) {
            rc = wc_MlDsaKey_ImportPrivRaw(mldsa, mem, inSz);
        }
        else
    #endif
        {
            rc = wc_MlDsaKey_ImportPubRaw(mldsa, mem, inSz);
        }
        if (rc == 0) {
            isMlDsa = 1;
        }
    }

    /* DER input includes auto level detection */
    if (!isMlDsa) {
        wc_MlDsaKey_Free(mldsa);
        if (wc_MlDsaKey_Init(mldsa, NULL, INVALID_DEVID) != 0) {
            WC_FREE_VAR_EX(mldsa, NULL, DYNAMIC_TYPE_MLDSA);
            return 0;
        }
    #if defined(WOLFSSL_MLDSA_PRIVATE_KEY) && !defined(WOLFSSL_MLDSA_NO_ASN1)
        if (priv) {
            rc = wc_MlDsaKey_PrivateKeyDecode(mldsa, mem, inSz, &keyIdx);
        }
        else
    #elif defined(WOLFSSL_MLDSA_PRIVATE_KEY) && defined(WOLFSSL_MLDSA_NO_ASN1)
        if (priv) {
            /* No PrivateKeyDecode without ASN.1 support. */
            rc = NOT_COMPILED_IN;
        }
        else
    #endif
        {
            rc = wc_MlDsaKey_PublicKeyDecode(mldsa, mem, inSz, &keyIdx);
        }
        if (rc == 0) {
            isMlDsa = 1;
        }
    }

    if (isMlDsa) {
        /* Level is already known from the successful import/decode above -
         * grab the OID now so callers don't need to re-decode the key
         * later just to recover it (e.g. wolfSSL_X509_verify()). */
        int keyFormat = 0;
        if (mldsa_get_oid_sum(mldsa, &keyFormat) == 0) {
            oidSum = keyFormat;
        }
    }

    wc_MlDsaKey_Free(mldsa);
    WC_FREE_VAR_EX(mldsa, NULL, DYNAMIC_TYPE_MLDSA);

    if (!isMlDsa) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* Copy the consumed DER into pkey->pkey.ptr, unless the caller
     * pre-filled the EVP PKEY with the input bytes (d2i_evp_pkey()).
     * A reused key must be re-populated here. */
    ret = 1;
    if (!prePopulated) {
        ret = d2i_make_pkey(out, mem, keyIdx, priv, WC_EVP_PKEY_DILITHIUM);
    }
    if ((ret == 1) && (out != NULL) && (*out != NULL) && (oidSum != 0)) {
        WOLFSSL_ATOMIC_STORE((*out)->mldsaOID, oidSum);
    }
    return ret;
}
#endif /* WOLFSSL_HAVE_MLDSA */

/**
 * Try to make a WOLFSSL_EVP_PKEY from data.
 *
 * @param [in, out] out    On in, an EVP PKEY or NULL.
 *                         On out, an EVP PKEY or NULL.
 * @param [in]      mem    Memory containing key data.
 * @param [in]      memSz  Size of key data in bytes.
 * @param [in]      priv   1 means private key, 0 means public key.
 * @return  Non-NULL WOLFSSL_EVP_PKEY* on success.
 * @return  NULL on bad arguments or unrecognized input type.
 */
static WOLFSSL_EVP_PKEY* d2i_evp_pkey_try(WOLFSSL_EVP_PKEY** out,
    const unsigned char** in, long inSz, int priv)
{
    WOLFSSL_EVP_PKEY* pkey = NULL;
    int found = 0;

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
        found = 1;
    }
    else
#endif /* NO_RSA */
#if defined(HAVE_ECC) && defined(OPENSSL_EXTRA)
    if (d2iTryEccKey(&pkey, *in, inSz, priv) >= 0) {
        found = 1;
    }
    else
#endif /* HAVE_ECC && OPENSSL_EXTRA */
#if !defined(NO_DSA)
    if (d2iTryDsaKey(&pkey, *in, inSz, priv) >= 0) {
        found = 1;
    }
    else
#endif /* NO_DSA */
#if !defined(NO_DH) && (defined(WOLFSSL_QT) || defined(OPENSSL_ALL))
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
    (HAVE_FIPS_VERSION > 2))
    if (d2iTryDhKey(&pkey, *in, inSz, priv) >= 0) {
        found = 1;
    }
    else
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH && (WOLFSSL_QT || OPENSSL_ALL) */

#if !defined(NO_DH) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_DH_EXTRA)
#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS_VERSION) && \
        (HAVE_FIPS_VERSION > 2))
    if (d2iTryAltDhKey(&pkey, *in, inSz, priv) >= 0) {
        found = 1;
    }
    else
#endif /* !HAVE_FIPS || HAVE_FIPS_VERSION > 2 */
#endif /* !NO_DH &&  OPENSSL_EXTRA && WOLFSSL_DH_EXTRA */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    if (d2iTryEd25519Key(&pkey, *in, inSz, priv, 0) >= 0) {
        found = 1;
    }
    else
#endif /* HAVE_ED25519 && HAVE_ED25519_KEY_IMPORT */
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
    if (d2iTryEd448Key(&pkey, *in, inSz, priv, 0) >= 0) {
        found = 1;
    }
    else
#endif /* HAVE_ED448 && HAVE_ED448_KEY_IMPORT */
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
    if (d2iTryX25519Key(&pkey, *in, inSz, priv, 0) >= 0) {
        found = 1;
    }
    else
#endif /* HAVE_CURVE25519 && HAVE_CURVE25519_KEY_IMPORT */
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT)
    if (d2iTryX448Key(&pkey, *in, inSz, priv, 0) >= 0) {
        found = 1;
    }
    else
#endif /* HAVE_CURVE448 && HAVE_CURVE448_KEY_IMPORT */
#ifdef HAVE_FALCON
    if (d2iTryFalconKey(&pkey, *in, inSz, priv) >= 0) {
        found = 1;
    }
    else
#endif /* HAVE_FALCON */
#ifdef WOLFSSL_HAVE_MLDSA
    if (d2iTryMlDsaKey(&pkey, *in, inSz, priv, 0, 1) >= 0) {
        found = 1;
    }
    else
#endif /* WOLFSSL_HAVE_MLDSA */
    {
        WOLFSSL_MSG("d2i_evp_pkey_try couldn't determine key type");
    }

    if (!found) {
        return NULL;
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
 * @return  NULL on failure. *out is left unchanged on failure; caller
 *          retains ownership of any pre-existing key passed via *out.
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
 * @return  NULL on failure. *out is left unchanged on failure; caller
 *          retains ownership of any pre-existing key passed via *out.
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
                wolfSSL_EVP_PKEY_free(key);
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
    if (in == NULL || *in == NULL || inSz <= 0) {
        WOLFSSL_MSG("Bad argument");
        return NULL;
    }

    if (priv == 1) {
        /* Check if input buffer has PKCS8 header. In the case that it does not
         * have a PKCS8 header then do not error out. */
        if ((ret = ToTraditionalInline_ex((const byte*)(*in), &idx,
                (word32)inSz, &algId)) >= 0) {
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
                (type == WC_EVP_PKEY_DH && algId != DHk)
            #ifdef HAVE_ED25519
                || (type == WC_EVP_PKEY_ED25519 && algId != ED25519k)
            #endif
            #ifdef HAVE_ED448
                || (type == WC_EVP_PKEY_ED448 && algId != ED448k)
            #endif
            #ifdef HAVE_CURVE25519
                || (type == WC_EVP_PKEY_X25519 && algId != X25519k)
            #endif
            #ifdef HAVE_CURVE448
                || (type == WC_EVP_PKEY_X448 && algId != X448k)
            #endif
            #ifdef WOLFSSL_HAVE_MLDSA
                || (type == WC_EVP_PKEY_DILITHIUM &&
                    algId != ML_DSA_44k && algId != ML_DSA_65k &&
                    algId != ML_DSA_87k
                #ifdef WOLFSSL_MLDSA_FIPS204_DRAFT
                    && algId != DILITHIUM_LEVEL2k
                    && algId != DILITHIUM_LEVEL3k
                    && algId != DILITHIUM_LEVEL5k
                #endif
                   )
            #endif
                ) {
                WOLFSSL_MSG("PKCS8 does not match EVP key type");
                return NULL;
            }

        #ifdef WOLFSSL_HAVE_MLDSA
            /* Keep the full PKCS#8 wrapper for ML-DSA so i2d retains the
             * parameter set held in the AlgorithmIdentifier. */
            if (type == WC_EVP_PKEY_DILITHIUM) {
                pkcs8HeaderSz = 0;
            }
        #endif

            (void)idx; /* not used */
        }
        /* Ensure no error occurred try to remove any PKCS#8 header. */
        else if (ret != WC_NO_ERR_TRACE(ASN_PARSE_E)) {
            WOLFSSL_MSG("Unexpected error with trying to remove PKCS8 header");
            return NULL;
        }
    }

    /* Create a new WOLFSSL_EVP_PKEY and populate. Any WOLFSSL_EVP_PKEY
     * passed in is replaced only on success. */
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
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
        case WC_EVP_PKEY_ED25519:
            /* local already holds the input bytes: prePopulated=1. */
            if (d2iTryEd25519Key(&local, p, local->pkey_sz, priv, 1) != 1) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* HAVE_ED25519 */
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
        case WC_EVP_PKEY_ED448:
            /* See WC_EVP_PKEY_ED25519 case above. */
            if (d2iTryEd448Key(&local, p, local->pkey_sz, priv, 1) != 1) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* HAVE_ED448 */
#if defined(HAVE_CURVE25519) && defined(HAVE_CURVE25519_KEY_IMPORT)
        case WC_EVP_PKEY_X25519:
            /* See WC_EVP_PKEY_ED25519 case above. */
            if (d2iTryX25519Key(&local, p, local->pkey_sz, priv, 1) != 1) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* HAVE_CURVE25519 && HAVE_CURVE25519_KEY_IMPORT */
#if defined(HAVE_CURVE448) && defined(HAVE_CURVE448_KEY_IMPORT)
        case WC_EVP_PKEY_X448:
            /* See WC_EVP_PKEY_ED25519 case above. */
            if (d2iTryX448Key(&local, p, local->pkey_sz, priv, 1) != 1) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* HAVE_CURVE448 && HAVE_CURVE448_KEY_IMPORT */
#if defined(WOLFSSL_HAVE_MLDSA)
        case WC_EVP_PKEY_DILITHIUM:
            /* local already holds the input bytes: prePopulated=1. */
            if (d2iTryMlDsaKey(&local, p, local->pkey_sz, priv, 1, 0) != 1) {
                wolfSSL_EVP_PKEY_free(local);
                return NULL;
            }
            break;
#endif /* WOLFSSL_HAVE_MLDSA */
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
            /* Dispose of any WOLFSSL_EVP_PKEY passed in. */
            wolfSSL_EVP_PKEY_free(*out);
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
    const byte* der;
    word32 idx = 0;
    int len = 0;
    int cnt = 0;
    word32 algId;
    word32 keyLen;

    if (pp == NULL || *pp == NULL || length <= 0)
        return NULL;

    der = *pp;
    keyLen = (word32)length;

    /* Take off PKCS#8 wrapper if found. */
    if ((len = ToTraditionalInline_ex(der, &idx, keyLen, &algId)) >= 0) {
    #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
        if (algId == ED25519k) {
            word32 seqIdx = 0;
            int seqLen = 0;

            /* Ed25519's inner key is an OCTET STRING, not a SEQUENCE, so the
             * RSA/ECC element-count heuristic below cannot classify it.
             * Decode the full PKCS#8 PrivateKeyInfo directly (keeps the
             * cached DER complete so the key can be re-loaded later).  Pass
             * the size of the whole PrivateKeyInfo, taken from its outer
             * SEQUENCE header: ToTraditionalInline_ex() reports the offset and
             * length of the inner privateKey OCTET STRING only, and RFC 5958
             * allows optional attributes and a publicKey to follow it - the
             * form wolfSSL's own wc_Ed25519KeyToDer() emits - which that offset
             * would cut off.  With the object size, *pp advances by exactly one
             * object and no trailing bytes are cached. */
            if (GetSequence(der, &seqIdx, &seqLen, keyLen) < 0) {
                return NULL;
            }
            return wolfSSL_d2i_PrivateKey(WC_EVP_PKEY_ED25519, pkey, pp,
                (long)seqIdx + (long)seqLen);
        }
    #endif
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
#ifdef HAVE_DILITHIUM
    word32 outerIdx = 0;
    int    outerLen = 0;
#endif

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
                 * in PKCS8 format */
                rawDer.buffer = pkcs8Der->buffer;
                rawDer.length = inOutIdx + (word32)ret;
            }
        #ifdef HAVE_DILITHIUM
            else if (
            #ifdef WOLFSSL_DILITHIUM_FIPS204_DRAFT
                (algId == DILITHIUM_LEVEL2k) ||
                (algId == DILITHIUM_LEVEL3k) ||
                (algId == DILITHIUM_LEVEL5k) ||
            #endif
                (algId == ML_DSA_44k) ||
                (algId == ML_DSA_65k) ||
                (algId == ML_DSA_87k)) {

                /* Keep full PKCS#8 wrapper for level recovery from
                 * AlgorithmIdentifier parameters */
                rawDer.buffer = pkcs8Der->buffer;
                if (GetSequence(pkcs8Der->buffer, &outerIdx, &outerLen,
                    pkcs8Der->length) < 0) {
                    ret = ASN_PARSE_E;
                }
                else {
                    rawDer.length = outerIdx + (word32)outerLen;
                }
            }
        #endif
            else {
                rawDer.buffer = pkcs8Der->buffer + inOutIdx;
                rawDer.length = (word32)ret;
            }
            if (ret > 0) {
                ret = 0; /* good DER */
            }
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

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
/* Encode an Ed25519 public key as DER SubjectPublicKeyInfo.  Follows the
 * i2d output convention: der == NULL returns the size only; *der == NULL
 * allocates the buffer (caller frees); otherwise writes into *der and
 * advances it.  Returns the DER size or WOLFSSL_FATAL_ERROR. */
static int wolfssl_i_i2d_ed25519_pubkey(const ed25519_key* key,
    unsigned char **der)
{
    int derSz;
    unsigned char* buf;

    if (key == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* withAlg = 1 -> wrap the raw key in a SubjectPublicKeyInfo. */
    derSz = wc_Ed25519PublicKeyToDer(key, NULL, 0, 1);
    if (derSz <= 0) {
        return WOLFSSL_FATAL_ERROR;
    }
    if (der == NULL) {
        return derSz;
    }

    if (*der != NULL) {
        /* Caller supplied the buffer: the size is known up front, so encode
         * straight into it and advance past the encoding. */
        if (wc_Ed25519PublicKeyToDer(key, *der, (word32)derSz, 1) != derSz) {
            return WOLFSSL_FATAL_ERROR;
        }
        *der += derSz;
        return derSz;
    }

    buf = (unsigned char*)XMALLOC((size_t)derSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    if (buf == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }
    if (wc_Ed25519PublicKeyToDer(key, buf, (word32)derSz, 1)
            != derSz) {
        XFREE(buf, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        return WOLFSSL_FATAL_ERROR;
    }
    /* Hand the buffer to the caller (no advance, per the i2d convention). */
    *der = buf;

    return derSz;
}
#endif /* HAVE_ED25519 && HAVE_ED25519_KEY_EXPORT */

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
    #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
        /* Emit a SubjectPublicKeyInfo (withAlg=1) rather than the bare key:
         * wolfSSL_i2d_PUBKEY aliases to this function (below), so the SPKI is
         * what wolfSSL_d2i_PUBKEY has to be able to read back.  Matches the
         * adjacent EC case, which encodes with withAlg=1 for the same reason.
         * (Note this differs from OpenSSL, where i2d_PublicKey emits the raw
         * key for Ed25519 and only i2d_PUBKEY emits the SPKI.) */
        case WC_EVP_PKEY_ED25519:
            return wolfssl_i_i2d_ed25519_pubkey(key->ed25519, der);
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

#ifndef NO_BIO
/* Encode public key as DER data and write to BIO.
 *
 * @param [in]  bio  BIO to write data to.
 * @param [in]  key  Public key to encode.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE on failure.
 */
int wolfSSL_i2d_PUBKEY_bio(WOLFSSL_BIO* bio, const WOLFSSL_EVP_PKEY* key)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    int derSz = 0;
    byte* der = NULL;
    byte* derPtr = NULL;

    WOLFSSL_ENTER("wolfSSL_i2d_PUBKEY_bio");

    if (bio == NULL || key == NULL) {
        return WOLFSSL_FAILURE;
    }

    derSz = wolfSSL_i2d_PUBKEY(key, NULL);
    if (derSz <= 0) {
        WOLFSSL_MSG("wolfSSL_i2d_PUBKEY size query failed");
        return WOLFSSL_FAILURE;
    }

    der = (byte*)XMALLOC((size_t)derSz, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL) {
        WOLFSSL_MSG("XMALLOC failed");
        return WOLFSSL_FAILURE;
    }

    derPtr = der;
    derSz = wolfSSL_i2d_PUBKEY(key, &derPtr);
    if (derSz <= 0) {
        WOLFSSL_MSG("wolfSSL_i2d_PUBKEY failed");
        goto cleanup;
    }

    /* A short write is reported as failure but is not rolled back: whatever
     * reached the BIO stays there, like OpenSSL's i2d_PUBKEY_bio. */
    if (wolfSSL_BIO_write(bio, der, derSz) != derSz) {
        WOLFSSL_MSG("wolfSSL_BIO_write failed; partial data may remain in BIO");
        goto cleanup;
    }

    ret = WOLFSSL_SUCCESS;

cleanup:
    XFREE(der, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* !NO_BIO */

#endif /* !NO_ASN && !NO_PWDBASED */

#endif /* OPENSSL_EXTRA */

#endif /* !NO_CERTS */

/*******************************************************************************
 * END OF i2d APIs
 ******************************************************************************/

#endif /* !WOLFSSL_EVP_PK_INCLUDED */

