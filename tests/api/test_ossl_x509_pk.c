/* test_ossl_x509_pk.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/ssl.h>
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

    wolfSSL_X509_free(x509);
#endif
    return EXPECT_RESULT();
}

