/* test_ossl_x509_pk.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/ssl.h>
#ifdef WOLFSSL_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif
#include <tests/utils.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_x509_pk.h>

int test_wolfSSL_X509_get_X509_PUBKEY(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_APACHE_HTTPD))
    X509* x509 = NULL;
    X509_PUBKEY* pubKey;

    ExpectNotNull(x509 = X509_new());

    ExpectNull(pubKey = wolfSSL_X509_get_X509_PUBKEY(NULL));
    ExpectNotNull(pubKey = wolfSSL_X509_get_X509_PUBKEY(x509));

    X509_free(x509);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_PUBKEY_RSA(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_APACHE_HTTPD)) && \
    !defined(NO_SHA256) && !defined(NO_RSA)
    X509* x509 = NULL;
    ASN1_OBJECT* obj = NULL;
    const ASN1_OBJECT* pa_oid = NULL;
    X509_PUBKEY* pubKey = NULL;
    X509_PUBKEY* pubKey2 = NULL;
    EVP_PKEY* evpKey = NULL;
    byte buf[1024];
    byte* tmp;

    const unsigned char *pk = NULL;
    int ppklen;
    int pptype;
    X509_ALGOR *pa = NULL;
    const void *pval;

    ExpectNotNull(x509 = X509_load_certificate_file(cliCertFile,
        SSL_FILETYPE_PEM));

    ExpectNotNull(pubKey = X509_get_X509_PUBKEY(x509));
    ExpectIntEQ(X509_PUBKEY_get0_param(&obj, &pk, &ppklen, &pa, pubKey), 1);
    ExpectNotNull(pk);
    ExpectNotNull(pa);
    ExpectNotNull(pubKey);
    ExpectIntGT(ppklen, 0);

    tmp = buf;
    ExpectIntEQ(wolfSSL_i2d_X509_PUBKEY(NULL, NULL), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_i2d_X509_PUBKEY(NULL, &tmp), WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_i2d_X509_PUBKEY(pubKey, NULL), 294);
    ExpectIntEQ(wolfSSL_i2d_X509_PUBKEY(pubKey, &tmp), 294);

    ExpectIntEQ(OBJ_obj2nid(obj), NID_rsaEncryption);

    ExpectNotNull(evpKey = X509_PUBKEY_get(pubKey));
    ExpectNotNull(pubKey2 = X509_PUBKEY_new());
    ExpectIntEQ(X509_PUBKEY_get0_param(&obj, &pk, &ppklen, &pa, NULL), 0);
    ExpectIntEQ(X509_PUBKEY_get0_param(&obj, &pk, &ppklen, &pa, pubKey2), 0);
    ExpectIntEQ(X509_PUBKEY_set(NULL, NULL), 0);
    ExpectIntEQ(X509_PUBKEY_set(&pubKey2, NULL), 0);
    ExpectIntEQ(X509_PUBKEY_set(NULL, evpKey), 0);
    ExpectIntEQ(X509_PUBKEY_set(&pubKey2, evpKey), 1);
    ExpectIntEQ(X509_PUBKEY_get0_param(NULL, NULL, NULL, NULL, pubKey2), 1);
    ExpectIntEQ(X509_PUBKEY_get0_param(&obj, &pk, &ppklen, &pa, pubKey2), 1);
    ExpectNotNull(pk);
    ExpectNotNull(pa);
    ExpectIntGT(ppklen, 0);
    X509_ALGOR_get0(&pa_oid, &pptype, &pval, pa);
    ExpectNotNull(pa_oid);
    ExpectNull(pval);
    ExpectIntEQ(pptype, V_ASN1_NULL);
    ExpectIntEQ(OBJ_obj2nid(pa_oid), EVP_PKEY_RSA);

    X509_PUBKEY_free(NULL);
    X509_PUBKEY_free(pubKey2);
    X509_free(x509);
    EVP_PKEY_free(evpKey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_PUBKEY_EC(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_APACHE_HTTPD)) && defined(HAVE_ECC)
    X509* x509 = NULL;
    ASN1_OBJECT* obj = NULL;
    ASN1_OBJECT* poid = NULL;
    const ASN1_OBJECT* pa_oid = NULL;
    X509_PUBKEY* pubKey = NULL;
    X509_PUBKEY* pubKey2 = NULL;
    EVP_PKEY* evpKey = NULL;

    const unsigned char *pk = NULL;
    int ppklen;
    int pptype;
    X509_ALGOR *pa = NULL;
    const void *pval;
    char buf[50];

    ExpectNotNull(x509 = X509_load_certificate_file(cliEccCertFile,
                                                    SSL_FILETYPE_PEM));
    ExpectNotNull(pubKey = X509_get_X509_PUBKEY(x509));
    ExpectNotNull(evpKey = X509_PUBKEY_get(pubKey));
    ExpectNotNull(pubKey2 = X509_PUBKEY_new());
    ExpectIntEQ(X509_PUBKEY_set(&pubKey2, evpKey), 1);
    ExpectIntEQ(X509_PUBKEY_get0_param(&obj, &pk, &ppklen, &pa, pubKey2), 1);
    ExpectNotNull(pk);
    ExpectNotNull(pa);
    ExpectIntGT(ppklen, 0);
    X509_ALGOR_get0(&pa_oid, &pptype, &pval, pa);
    ExpectNotNull(pa_oid);
    ExpectNotNull(pval);
    ExpectIntEQ(pptype, V_ASN1_OBJECT);
    ExpectIntEQ(OBJ_obj2nid(pa_oid), EVP_PKEY_EC);
    poid = (ASN1_OBJECT *)pval;
    ExpectIntGT(OBJ_obj2txt(buf, (int)sizeof(buf), poid, 0), 0);
    ExpectIntEQ(OBJ_txt2nid(buf), NID_X9_62_prime256v1);

    X509_PUBKEY_free(pubKey2);
    X509_free(x509);
    EVP_PKEY_free(evpKey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_PUBKEY_DSA(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_APACHE_HTTPD)) && !defined(NO_DSA)
    word32  bytes;
#ifdef USE_CERT_BUFFERS_1024
    byte    tmp[ONEK_BUF];
#elif defined(USE_CERT_BUFFERS_2048)
    byte    tmp[TWOK_BUF];
#else
    byte    tmp[TWOK_BUF];
#endif /* END USE_CERT_BUFFERS_1024 */
    const unsigned char* dsaKeyDer = tmp;

    ASN1_OBJECT* obj = NULL;
    ASN1_STRING* str;
    const ASN1_OBJECT* pa_oid = NULL;
    X509_PUBKEY* pubKey = NULL;
    EVP_PKEY* evpKey = NULL;

    const unsigned char *pk = NULL;
    int ppklen, pptype;
    X509_ALGOR *pa = NULL;
    const void *pval;

#ifdef USE_CERT_BUFFERS_1024
    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMCPY(tmp, dsa_key_der_1024, sizeof_dsa_key_der_1024);
    bytes = sizeof_dsa_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    XMEMSET(tmp, 0, sizeof(tmp));
    XMEMCPY(tmp, dsa_key_der_2048, sizeof_dsa_key_der_2048);
    bytes = sizeof_dsa_key_der_2048;
#else
    {
        XFILE fp = XBADFILE;
        XMEMSET(tmp, 0, sizeof(tmp));
        ExpectTrue((fp = XFOPEN("./certs/dsa2048.der", "rb")) != XBADFILE);
        ExpectIntGT(bytes = (word32) XFREAD(tmp, 1, sizeof(tmp), fp), 0);
        if (fp != XBADFILE)
            XFCLOSE(fp);
    }
#endif

    /* Initialize pkey with der format dsa key */
    ExpectNotNull(d2i_PrivateKey(EVP_PKEY_DSA, &evpKey, &dsaKeyDer, bytes));

    ExpectNotNull(pubKey = X509_PUBKEY_new());
    ExpectIntEQ(X509_PUBKEY_set(&pubKey, evpKey), 1);
    ExpectIntEQ(X509_PUBKEY_get0_param(&obj, &pk, &ppklen, &pa, pubKey), 1);
    ExpectNotNull(pk);
    ExpectNotNull(pa);
    ExpectIntGT(ppklen, 0);
    X509_ALGOR_get0(&pa_oid, &pptype, &pval, pa);
    ExpectNotNull(pa_oid);
    ExpectNotNull(pval);
    ExpectIntEQ(pptype, V_ASN1_SEQUENCE);
    ExpectIntEQ(OBJ_obj2nid(pa_oid), EVP_PKEY_DSA);
    str = (ASN1_STRING *)pval;
    DEBUG_WRITE_DER(ASN1_STRING_data(str), ASN1_STRING_length(str), "str.der");
#ifdef USE_CERT_BUFFERS_1024
    ExpectIntEQ(ASN1_STRING_length(str), 291);
#else
    ExpectIntEQ(ASN1_STRING_length(str), 549);
#endif /* END USE_CERT_BUFFERS_1024 */

    X509_PUBKEY_free(pubKey);
    EVP_PKEY_free(evpKey);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_PUBKEY_get(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    WOLFSSL_X509_PUBKEY pubkey;
    WOLFSSL_X509_PUBKEY* key;
    WOLFSSL_EVP_PKEY evpkey ;
    WOLFSSL_EVP_PKEY* evpPkey;
    WOLFSSL_EVP_PKEY* retEvpPkey;

    XMEMSET(&pubkey, 0, sizeof(WOLFSSL_X509_PUBKEY));
    XMEMSET(&evpkey, 0, sizeof(WOLFSSL_EVP_PKEY));

    key = &pubkey;
    evpPkey = &evpkey;

    evpPkey->type = WOLFSSL_SUCCESS;
    key->pkey = evpPkey;

    ExpectNotNull(retEvpPkey = wolfSSL_X509_PUBKEY_get(key));
    ExpectIntEQ(retEvpPkey->type, WOLFSSL_SUCCESS);

    ExpectNull(retEvpPkey = wolfSSL_X509_PUBKEY_get(NULL));

    key->pkey = NULL;
    ExpectNull(retEvpPkey = wolfSSL_X509_PUBKEY_get(key));
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_set_pubkey(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_ALL
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;

    ExpectNotNull(x509 = wolfSSL_X509_new());

#if !defined(NO_RSA)
    {
        WOLFSSL_RSA* rsa = NULL;

        ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
        if (pkey != NULL) {
            pkey->type = WC_EVP_PKEY_RSA;
        }
        ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey), WOLFSSL_FAILURE);
        ExpectNotNull(rsa = wolfSSL_RSA_new());
        ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa),
            WOLFSSL_SUCCESS);
        if (EXPECT_FAIL()) {
            wolfSSL_RSA_free(rsa);
        }
        ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey), WOLFSSL_SUCCESS);
        wolfSSL_EVP_PKEY_free(pkey);
        pkey = NULL;
    }
#endif
#if !defined(HAVE_SELFTEST) && (defined(WOLFSSL_KEY_GEN) || \
        defined(WOLFSSL_CERT_GEN)) && !defined(NO_DSA)
    {
        WOLFSSL_DSA* dsa = NULL;

        ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
        if (pkey != NULL) {
            pkey->type = WC_EVP_PKEY_DSA;
        }
        ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey), WOLFSSL_FAILURE);
        ExpectNotNull(dsa = wolfSSL_DSA_new());
        ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa),
            WOLFSSL_SUCCESS);
        if (EXPECT_FAIL()) {
            wolfSSL_DSA_free(dsa);
        }
        ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey), WOLFSSL_FAILURE);
        wolfSSL_EVP_PKEY_free(pkey);
        pkey = NULL;
    }
#endif
#if defined(HAVE_ECC)
    {
        WOLFSSL_EC_KEY* ec = NULL;

        ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
        if (pkey != NULL) {
            pkey->type = WC_EVP_PKEY_EC;
        }
        ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey), WOLFSSL_FAILURE);
        ExpectNotNull(ec = wolfSSL_EC_KEY_new());
        ExpectIntEQ(wolfSSL_EC_KEY_generate_key(ec), 1);
        ExpectIntEQ(wolfSSL_EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec),
            WOLFSSL_SUCCESS);
        if (EXPECT_FAIL()) {
            wolfSSL_EC_KEY_free(ec);
        }
        ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey), WOLFSSL_SUCCESS);
        wolfSSL_EVP_PKEY_free(pkey);
        pkey = NULL;
    }
#endif
#if !defined(NO_DH)
    ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
    if (pkey != NULL) {
        pkey->type = WC_EVP_PKEY_DH;
    }
    ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey), WOLFSSL_FAILURE);
    wolfSSL_EVP_PKEY_free(pkey);
    pkey = NULL;
#endif
#if defined(WOLFSSL_HAVE_MLDSA) && defined(WOLFSSL_MLDSA_PRIVATE_KEY) && \
    defined(WOLFSSL_MLDSA_PUBLIC_KEY) && !defined(WOLFSSL_MLDSA_NO_ASN1) && \
    defined(WC_ENABLE_ASYM_KEY_EXPORT) && !defined(NO_FILESYSTEM) && \
    !defined(NO_BIO) && !defined(WOLFSSL_NO_ML_DSA_44)
    {
        WOLFSSL_BIO* bio = NULL;
        WOLFSSL_EVP_PKEY* pubkey = NULL;

        /* EVP_PKEY with no key data */
        ExpectNotNull(pkey = wolfSSL_EVP_PKEY_new());
        if (pkey != NULL) {
            pkey->type = WC_EVP_PKEY_DILITHIUM;
        }
        ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey), WOLFSSL_FAILURE);
        wolfSSL_EVP_PKEY_free(pkey);
        pkey = NULL;

        /* ML-DSA keys loaded from file: cover every compiled-in level.
         * ML-DSA-87 (2592-byte public key, 4627-byte signature) is what
         * motivates the enlarged DER buffers. */
        {
            static const char* keyFiles[] = {
                "./certs/mldsa/mldsa44-key.pem",
            #ifndef WOLFSSL_NO_ML_DSA_65
                "./certs/mldsa/mldsa65-key.pem",
            #endif
            #ifndef WOLFSSL_NO_ML_DSA_87
                "./certs/mldsa/mldsa87-key.pem",
            #endif
            };
            size_t ki;

            for (ki = 0; ki < sizeof(keyFiles) / sizeof(keyFiles[0]); ki++) {
                ExpectNotNull(bio = wolfSSL_BIO_new_file(keyFiles[ki], "rb"));
                ExpectNotNull(pkey = wolfSSL_PEM_read_bio_PrivateKey(bio,
                    NULL, NULL, NULL));
                wolfSSL_BIO_free(bio);
                bio = NULL;
                ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey),
                    WOLFSSL_SUCCESS);

                /* public key can be retrieved and has the right type */
                ExpectNotNull(pubkey = wolfSSL_X509_get_pubkey(x509));
                ExpectIntEQ(wolfSSL_EVP_PKEY_id(pubkey),
                    WC_EVP_PKEY_DILITHIUM);
                wolfSSL_EVP_PKEY_free(pubkey);
                pubkey = NULL;

            #if defined(WOLFSSL_CERT_GEN) && !defined(NO_PWDBASED) && \
                !defined(WOLFSSL_MLDSA_NO_SIGN) && \
                !defined(WOLFSSL_MLDSA_NO_VERIFY)
                /* sign and verify round trip with the ML-DSA key */
                {
                    WOLFSSL_X509_NAME* name = NULL;

                    ExpectNotNull(name = wolfSSL_X509_NAME_new());
                    ExpectIntEQ(wolfSSL_X509_NAME_add_entry_by_txt(name,
                        "CN", MBSTRING_UTF8, (const byte*)"mldsa-test", -1,
                        -1, 0), WOLFSSL_SUCCESS);
                    ExpectIntEQ(wolfSSL_X509_set_subject_name(x509, name),
                        WOLFSSL_SUCCESS);
                    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name),
                        WOLFSSL_SUCCESS);
                    wolfSSL_X509_NAME_free(name);

                    ExpectIntGT(wolfSSL_X509_sign(x509, pkey,
                        wolfSSL_EVP_sha256()), 0);
                    ExpectNotNull(pubkey = wolfSSL_X509_get_pubkey(x509));
                    ExpectIntEQ(wolfSSL_X509_verify(x509, pubkey),
                        WOLFSSL_SUCCESS);
                    wolfSSL_EVP_PKEY_free(pubkey);
                    pubkey = NULL;

                    /* OpenSSL semantics: NULL md is valid for ML-DSA. */
                    ExpectIntGT(wolfSSL_X509_sign(x509, pkey, NULL), 0);
                    ExpectNotNull(pubkey = wolfSSL_X509_get_pubkey(x509));
                    ExpectIntEQ(wolfSSL_X509_verify(x509, pubkey),
                        WOLFSSL_SUCCESS);
                    wolfSSL_EVP_PKEY_free(pubkey);
                    pubkey = NULL;

                    /* A stale/tampered mldsaOID cache must fail the sign
                     * rather than emit a certificate whose
                     * signatureAlgorithm disagrees with the actual key. */
                    if (EXPECT_SUCCESS() && pkey != NULL) {
                        int realOID = WOLFSSL_ATOMIC_LOAD(pkey->mldsaOID);
                        int wrongOID = (realOID == ML_DSA_44k) ?
                            ML_DSA_65k : ML_DSA_44k;
                        WOLFSSL_ATOMIC_STORE(pkey->mldsaOID, wrongOID);
                        ExpectIntEQ(wolfSSL_X509_sign(x509, pkey, NULL),
                            WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
                        WOLFSSL_ATOMIC_STORE(pkey->mldsaOID, realOID);
                    }
                }
            #endif
                if (ki + 1 < sizeof(keyFiles) / sizeof(keyFiles[0])) {
                    wolfSSL_EVP_PKEY_free(pkey);
                    pkey = NULL;
                }
            }
        }

        /* Public-only EVP_PKEY holding an SPKI: the private-key decode
         * fails and the fallback public decode must work on a reset key. */
        {
            WOLFSSL_EVP_PKEY* spki = NULL;
            unsigned char* der = NULL;
            int derSz = 0;
            const unsigned char* pp;
            XFILE f = XBADFILE;

            ExpectNotNull(der = (unsigned char*)XMALLOC(2048, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
            ExpectTrue((f = XFOPEN("./certs/mldsa/mldsa44_pub-spki.der",
                "rb")) != XBADFILE);
            ExpectIntGT(derSz = (int)XFREAD(der, 1, 2048, f), 0);
            if (f != XBADFILE) {
                XFCLOSE(f);
                f = XBADFILE;
            }
            pp = der;
            ExpectNotNull(spki = wolfSSL_d2i_PUBKEY(NULL, &pp, (long)derSz));
            ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, spki), WOLFSSL_SUCCESS);
            ExpectNotNull(pubkey = wolfSSL_X509_get_pubkey(x509));
            ExpectIntEQ(wolfSSL_EVP_PKEY_id(pubkey), WC_EVP_PKEY_DILITHIUM);
            wolfSSL_EVP_PKEY_free(pubkey);
            pubkey = NULL;
            wolfSSL_EVP_PKEY_free(spki);
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        wolfSSL_EVP_PKEY_free(pkey);
        pkey = NULL;

        /* PKCS#8 shapes: a seed-carrying key derives the public half so
         * set_pubkey succeeds. For a private-only blob the outcome tracks
         * whether wolfCrypt can derive the public half on demand in
         * wc_MlDsaKey_PublicKeyToDer() (added by PR #10985). */
        {
            unsigned char* der = NULL;
            int derSz = 0;
            const unsigned char* pp;
            XFILE f = XBADFILE;

            ExpectNotNull(der = (unsigned char*)XMALLOC(4096, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
        #ifndef WOLFSSL_MLDSA_VERIFY_ONLY
            ExpectTrue((f = XFOPEN("./certs/mldsa/mldsa44_seed-priv.der",
                "rb")) != XBADFILE);
            ExpectIntGT(derSz = (int)XFREAD(der, 1, 4096, f), 0);
            if (f != XBADFILE) {
                XFCLOSE(f);
                f = XBADFILE;
            }
            pp = der;
            ExpectNotNull(pkey = wolfSSL_d2i_PrivateKey(
                WC_EVP_PKEY_DILITHIUM, NULL, &pp, (long)derSz));
            ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey),
                WOLFSSL_SUCCESS);
            wolfSSL_EVP_PKEY_free(pkey);
            pkey = NULL;
        #endif

            ExpectTrue((f = XFOPEN("./certs/mldsa/mldsa44_priv-only.der",
                "rb")) != XBADFILE);
            ExpectIntGT(derSz = (int)XFREAD(der, 1, 4096, f), 0);
            if (f != XBADFILE) {
                XFCLOSE(f);
                f = XBADFILE;
            }
            {
                wc_MlDsaKey* rawKey = NULL;
                byte* pubDer = NULL;
                word32 kidx = 0;
                int expected = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
                int keyRet = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

                ExpectNotNull(pubDer = (byte*)XMALLOC(
                    MLDSA_MAX_PUB_KEY_DER_SIZE, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER));
                ExpectNotNull(rawKey = (wc_MlDsaKey*)XMALLOC(sizeof(*rawKey),
                    NULL, DYNAMIC_TYPE_TMP_BUFFER));
                ExpectIntEQ(keyRet = wc_MlDsaKey_Init(rawKey, NULL,
                    INVALID_DEVID), 0);
                PRIVATE_KEY_UNLOCK();
                ExpectIntEQ(wc_MlDsaKey_PrivateKeyDecode(rawKey, der,
                    (word32)derSz, &kidx), 0);
                if (EXPECT_SUCCESS() &&
                        wc_MlDsaKey_PublicKeyToDer(rawKey, pubDer,
                            MLDSA_MAX_PUB_KEY_DER_SIZE, 1) > 0) {
                    expected = WOLFSSL_SUCCESS;
                }
                PRIVATE_KEY_LOCK();
                if (keyRet == 0) {
                    wc_MlDsaKey_Free(rawKey);
                }
                XFREE(rawKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(pubDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);

                pp = der;
                ExpectNotNull(pkey = wolfSSL_d2i_PrivateKey(
                    WC_EVP_PKEY_DILITHIUM, NULL, &pp, (long)derSz));
                ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey), expected);
                wolfSSL_EVP_PKEY_free(pkey);
                pkey = NULL;
            }
            XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

    #if defined(WOLFSSL_MLDSA_FIPS204_DRAFT) && \
        !defined(WOLFSSL_MLDSA_VERIFY_ONLY) && defined(WOLFSSL_CERT_GEN) && \
        !defined(NO_PWDBASED) && !defined(WOLFSSL_MLDSA_NO_SIGN) && \
        !defined(WOLFSSL_MLDSA_NO_VERIFY) && !defined(WOLFSSL_NO_ML_DSA_44)
        /* FIPS204-draft Dilithium key: set_pubkey must keep pubKeyOID
         * consistent with the draft-OID SPKI emitted by
         * wc_MlDsaKey_PublicKeyToDer(), or the subsequent sign fails. */
        {
            wc_MlDsaKey* draftKey = NULL;
            WC_RNG rng;
            byte* draftDer = NULL;
            int draftDerSz = 0;
            const unsigned char* dp;
            int rngRet = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
            int keyRet = WC_NO_ERR_TRACE(BAD_FUNC_ARG);

            ExpectNotNull(draftDer = (byte*)XMALLOC(4096, NULL,
                DYNAMIC_TYPE_TMP_BUFFER));
            ExpectNotNull(draftKey = (wc_MlDsaKey*)XMALLOC(sizeof(*draftKey),
                NULL, DYNAMIC_TYPE_TMP_BUFFER));
            ExpectIntEQ(rngRet = wc_InitRng(&rng), 0);
            ExpectIntEQ(keyRet = wc_MlDsaKey_Init(draftKey, NULL,
                INVALID_DEVID), 0);
            ExpectIntEQ(wc_MlDsaKey_SetParams(draftKey, WC_ML_DSA_44_DRAFT),
                0);
            ExpectIntEQ(wc_MlDsaKey_MakeKey(draftKey, &rng), 0);
            /* KeyToDer (priv+pub): the decode of a priv-only PKCS#8 does
             * not derive the public part needed by PublicKeyToDer. */
            PRIVATE_KEY_UNLOCK();
            ExpectIntGT(draftDerSz = wc_MlDsaKey_KeyToDer(draftKey,
                draftDer, 4096), 0);
            PRIVATE_KEY_LOCK();
            if (keyRet == 0) {
                wc_MlDsaKey_Free(draftKey);
            }
            XFREE(draftKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (rngRet == 0) {
                wc_FreeRng(&rng);
            }

            dp = draftDer;
            ExpectNotNull(pkey = wolfSSL_d2i_PrivateKey(
                WC_EVP_PKEY_DILITHIUM, NULL, &dp, (long)draftDerSz));
            ExpectIntEQ(wolfSSL_X509_set_pubkey(x509, pkey),
                WOLFSSL_SUCCESS);
            ExpectIntGT(wolfSSL_X509_sign(x509, pkey, NULL), 0);
            ExpectNotNull(pubkey = wolfSSL_X509_get_pubkey(x509));
            ExpectIntEQ(wolfSSL_X509_verify(x509, pubkey), WOLFSSL_SUCCESS);
            wolfSSL_EVP_PKEY_free(pubkey);
            pubkey = NULL;
            wolfSSL_EVP_PKEY_free(pkey);
            pkey = NULL;
            XFREE(draftDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    #endif /* WOLFSSL_MLDSA_FIPS204_DRAFT */
    }
#endif /* WOLFSSL_HAVE_MLDSA */

#if defined(WOLFSSL_HAVE_MLDSA) && defined(WOLFSSL_MLDSA_PRIVATE_KEY) && \
    defined(WOLFSSL_MLDSA_PUBLIC_KEY) && !defined(WOLFSSL_MLDSA_NO_ASN1) && \
    defined(WC_ENABLE_ASYM_KEY_EXPORT) && !defined(NO_FILESYSTEM) && \
    !defined(NO_BIO) && !defined(WOLFSSL_NO_ML_DSA_87) && \
    !defined(NO_RSA) && defined(USE_CERT_BUFFERS_2048) && \
    defined(WOLFSSL_CERT_GEN) && !defined(NO_PWDBASED)
    {
        /* Classic-signed certificate carrying a large ML-DSA-87 subject
         * public key: the DER buffer must be sized for the subject SPKI
         * even though the signing key is RSA. */
        WOLFSSL_X509* cx = NULL;
        WOLFSSL_EVP_PKEY* mldsaKey = NULL;
        WOLFSSL_EVP_PKEY* rsaKey = NULL;
        WOLFSSL_EVP_PKEY* pub = NULL;
        WOLFSSL_X509_NAME* name = NULL;
        WOLFSSL_BIO* bio = NULL;
        const unsigned char* p = client_key_der_2048;

        ExpectNotNull(bio = wolfSSL_BIO_new_file(
            "./certs/mldsa/mldsa87-key.pem", "rb"));
        ExpectNotNull(mldsaKey = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL,
            NULL, NULL));
        wolfSSL_BIO_free(bio);
        bio = NULL;
        ExpectNotNull(rsaKey = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p,
            (long)sizeof_client_key_der_2048));

        ExpectNotNull(cx = wolfSSL_X509_new());
        ExpectNotNull(name = wolfSSL_X509_NAME_new());
        ExpectIntEQ(wolfSSL_X509_NAME_add_entry_by_txt(name, "CN",
            MBSTRING_UTF8, (const byte*)"mldsa87-subject", -1, -1, 0),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_X509_set_subject_name(cx, name), WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_X509_set_issuer_name(cx, name), WOLFSSL_SUCCESS);
        wolfSSL_X509_NAME_free(name);
        ExpectIntEQ(wolfSSL_X509_set_pubkey(cx, mldsaKey), WOLFSSL_SUCCESS);

        /* NULL md is still rejected for a hash-based signing key. */
        ExpectIntEQ(wolfSSL_X509_sign(cx, rsaKey, NULL), WOLFSSL_FAILURE);

        ExpectIntGT(wolfSSL_X509_sign(cx, rsaKey, wolfSSL_EVP_sha256()), 0);

        /* Subject public key kept its type; signature checks out with the
         * RSA issuer key. */
        ExpectNotNull(pub = wolfSSL_X509_get_pubkey(cx));
        ExpectIntEQ(wolfSSL_EVP_PKEY_id(pub), WC_EVP_PKEY_DILITHIUM);
        wolfSSL_EVP_PKEY_free(pub);
        pub = NULL;
        {
            const unsigned char* pp = client_keypub_der_2048;
            ExpectNotNull(pub = wolfSSL_d2i_PUBKEY(NULL, &pp,
                (long)sizeof_client_keypub_der_2048));
            ExpectIntEQ(wolfSSL_X509_verify(cx, pub), WOLFSSL_SUCCESS);
            wolfSSL_EVP_PKEY_free(pub);
            pub = NULL;
        }

        wolfSSL_EVP_PKEY_free(rsaKey);
        wolfSSL_EVP_PKEY_free(mldsaKey);
        wolfSSL_X509_free(cx);
    }
#endif /* classic-signed cert with ML-DSA-87 subject key */

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

