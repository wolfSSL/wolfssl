/* test_ossl_x509_crypto.c
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
#include <wolfssl/internal.h>
#include <tests/utils.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_x509_crypto.h>

int test_wolfSSL_X509_check_private_key(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_RSA) && \
        defined(USE_CERT_BUFFERS_2048) && !defined(NO_CHECK_PRIVATE_KEY) && \
        !defined(NO_FILESYSTEM)
    X509*  x509 = NULL;
    EVP_PKEY* pkey = NULL;
    const byte* key;

    /* Check with correct key */
    ExpectNotNull((x509 = X509_load_certificate_file(cliCertFile,
        SSL_FILETYPE_PEM)));
    key = client_key_der_2048;
    ExpectNotNull(d2i_PrivateKey(EVP_PKEY_RSA, &pkey, &key,
        (long)sizeof_client_key_der_2048));
    ExpectIntEQ(X509_check_private_key(x509, pkey), 1);
    EVP_PKEY_free(pkey);
    pkey = NULL;

    /* Check with wrong key */
    key = server_key_der_2048;
    ExpectNotNull(d2i_PrivateKey(EVP_PKEY_RSA, &pkey, &key,
        (long)sizeof_server_key_der_2048));
    ExpectIntEQ(X509_check_private_key(x509, pkey), 0);

    /* test for incorrect parameter */
    ExpectIntEQ(X509_check_private_key(NULL, pkey), 0);
    ExpectIntEQ(X509_check_private_key(x509, NULL), 0);
    ExpectIntEQ(X509_check_private_key(NULL, NULL), 0);

    EVP_PKEY_free(pkey);
    X509_free(x509);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_verify(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_RSA) && !defined(NO_FILESYSTEM) && \
    defined(OPENSSL_EXTRA)
    WOLFSSL_X509* ca = NULL;
    WOLFSSL_X509* serv = NULL;
    WOLFSSL_EVP_PKEY* pkey = NULL;
    unsigned char buf[2048];
    const unsigned char* pt = NULL;
    int bufSz = 0;

    ExpectNotNull(ca = wolfSSL_X509_load_certificate_file(caCertFile,
        WOLFSSL_FILETYPE_PEM));

    ExpectIntNE(wolfSSL_X509_get_pubkey_buffer(NULL, buf, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntNE(wolfSSL_X509_get_pubkey_buffer(NULL, buf, &bufSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_get_pubkey_buffer(ca, NULL, &bufSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(bufSz, 294);

    bufSz--;
    ExpectIntNE(wolfSSL_X509_get_pubkey_buffer(ca, buf, &bufSz),
        WOLFSSL_SUCCESS);
    bufSz = 2048;
    ExpectIntEQ(wolfSSL_X509_get_pubkey_buffer(ca, buf, &bufSz),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_get_pubkey_type(NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(wolfSSL_X509_get_pubkey_type(ca), RSAk);


    ExpectNotNull(serv = wolfSSL_X509_load_certificate_file(svrCertFile,
        WOLFSSL_FILETYPE_PEM));

    /* success case */
    pt = buf;
    ExpectNotNull(pkey = wolfSSL_d2i_PUBKEY(NULL, &pt, bufSz));

    ExpectIntEQ(i2d_PUBKEY(pkey, NULL), bufSz);

    ExpectIntEQ(wolfSSL_X509_verify(serv, pkey), WOLFSSL_SUCCESS);
    wolfSSL_EVP_PKEY_free(pkey);
    pkey = NULL;

    /* fail case */
    bufSz = 2048;
    ExpectIntEQ(wolfSSL_X509_get_pubkey_buffer(serv, buf, &bufSz),
        WOLFSSL_SUCCESS);
    pt = buf;
    ExpectNotNull(pkey = wolfSSL_d2i_PUBKEY(NULL, &pt, bufSz));
    ExpectIntEQ(wolfSSL_X509_verify(serv, pkey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    ExpectIntEQ(wolfSSL_X509_verify(NULL, pkey),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));
    ExpectIntEQ(wolfSSL_X509_verify(serv, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR));

#ifndef NO_WOLFSSL_STUB
    ExpectNull(wolfSSL_X509_get0_pubkey_bitstr(NULL));
    ExpectNull(wolfSSL_X509_get0_pubkey_bitstr(serv));
#endif

    wolfSSL_EVP_PKEY_free(pkey);

    wolfSSL_FreeX509(ca);
    wolfSSL_FreeX509(serv);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_sign(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_ASN_TIME) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ) && !defined(NO_RSA)
    int ret = 0;
    char *cn = NULL;
    word32 cnSz = 0;
    X509_NAME *name = NULL;
    X509_NAME *emptyName = NULL;
    X509 *x509 = NULL;
    X509 *ca = NULL;
    DecodedCert dCert;
    EVP_PKEY *pub = NULL;
    EVP_PKEY *priv = NULL;
    EVP_MD_CTX *mctx = NULL;
#if defined(USE_CERT_BUFFERS_1024)
    const unsigned char* rsaPriv = client_key_der_1024;
    const unsigned char* rsaPub = client_keypub_der_1024;
    const unsigned char* certIssuer = client_cert_der_1024;
    long clientKeySz = (long)sizeof_client_key_der_1024;
    long clientPubKeySz = (long)sizeof_client_keypub_der_1024;
    long certIssuerSz = (long)sizeof_client_cert_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    const unsigned char* rsaPriv = client_key_der_2048;
    const unsigned char* rsaPub = client_keypub_der_2048;
    const unsigned char* certIssuer = client_cert_der_2048;
    long clientKeySz = (long)sizeof_client_key_der_2048;
    long clientPubKeySz = (long)sizeof_client_keypub_der_2048;
    long certIssuerSz = (long)sizeof_client_cert_der_2048;
#endif
    byte sn[16];
    int snSz = sizeof(sn);
    int sigSz = 0;
#ifndef NO_WOLFSSL_STUB
    const WOLFSSL_ASN1_BIT_STRING* sig = NULL;
    const WOLFSSL_X509_ALGOR* alg = NULL;
#endif

    /* Set X509_NAME fields */
    ExpectNotNull(name = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName", MBSTRING_UTF8,
                                       (byte*)"US", 2, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                             (byte*)"wolfssl.com", 11, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_UTF8,
                     (byte*)"support@wolfssl.com", 19, -1, 0), SSL_SUCCESS);

    /* Get private and public keys */
    ExpectNotNull(priv = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL, &rsaPriv,
                                                                  clientKeySz));
    ExpectNotNull(pub = wolfSSL_d2i_PUBKEY(NULL, &rsaPub, clientPubKeySz));
    ExpectNotNull(x509 = X509_new());
    ExpectIntEQ(X509_sign(x509, priv, EVP_sha256()), 0);
    /* Set version 3 */
    ExpectIntNE(X509_set_version(x509, 2L), 0);
    /* Set subject name, add pubkey, and sign certificate */
    ExpectIntEQ(X509_set_subject_name(x509, name), SSL_SUCCESS);
    X509_NAME_free(name);
    name = NULL;
    ExpectIntEQ(X509_set_pubkey(x509, pub), SSL_SUCCESS);
#ifdef WOLFSSL_ALT_NAMES
    ExpectNull(wolfSSL_X509_get_next_altname(NULL));
    ExpectNull(wolfSSL_X509_get_next_altname(x509));

    /* Add some subject alt names */
    ExpectIntNE(wolfSSL_X509_add_altname(NULL,
                "ipsum", ASN_DNS_TYPE), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_altname(x509,
                NULL, ASN_DNS_TYPE), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_altname(x509,
                "sphygmomanometer",
                ASN_DNS_TYPE), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_altname(x509,
                "supercalifragilisticexpialidocious",
                ASN_DNS_TYPE), SSL_SUCCESS);
    ExpectIntEQ(wolfSSL_X509_add_altname(x509,
                "Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch",
                ASN_DNS_TYPE), SSL_SUCCESS);
#ifdef WOLFSSL_IP_ALT_NAME
    {
        unsigned char ip4_type[] = {127,128,0,255};
        unsigned char ip6_type[] = {0xdd, 0xcc, 0xba, 0xab,
                                    0xff, 0xee, 0x99, 0x88,
                                    0x77, 0x66, 0x55, 0x44,
                                    0x00, 0x33, 0x22, 0x11};
        ExpectIntEQ(wolfSSL_X509_add_altname_ex(x509, (char*)ip4_type,
                sizeof(ip4_type), ASN_IP_TYPE), SSL_SUCCESS);
        ExpectIntEQ(wolfSSL_X509_add_altname_ex(x509, (char*)ip6_type,
                sizeof(ip6_type), ASN_IP_TYPE), SSL_SUCCESS);
    }
#endif

    {
        int i;

        if (x509 != NULL) {
            x509->altNamesNext = x509->altNames;
        }
#ifdef WOLFSSL_IP_ALT_NAME
        /* No names in IP address. */
        ExpectNull(wolfSSL_X509_get_next_altname(x509));
        ExpectNull(wolfSSL_X509_get_next_altname(x509));
#endif
        for (i = 0; i < 3; i++) {
            ExpectNotNull(wolfSSL_X509_get_next_altname(x509));
        }
        ExpectNull(wolfSSL_X509_get_next_altname(x509));
#ifdef WOLFSSL_MULTICIRCULATE_ALTNAMELIST
        ExpectNotNull(wolfSSL_X509_get_next_altname(x509));
#endif
    }
#endif /* WOLFSSL_ALT_NAMES */

    {
        ASN1_UTCTIME* infinite_past = NULL;
        ExpectNotNull(infinite_past = ASN1_UTCTIME_set(NULL, 0));
        ExpectIntEQ(X509_set1_notBefore(x509, infinite_past), 1);
        ASN1_UTCTIME_free(infinite_past);
    }

    /* test valid sign case */
    ExpectIntGT(ret = X509_sign(x509, priv, EVP_sha256()), 0);
    /* test getting signature */
#ifndef NO_WOLFSSL_STUB
    wolfSSL_X509_get0_signature(&sig, &alg, x509);
#endif
    ExpectIntEQ(wolfSSL_X509_get_signature(x509, NULL, &sigSz),
        WOLFSSL_SUCCESS);
    ExpectIntGT(sigSz, 0);
    ExpectIntEQ(wolfSSL_X509_get_signature(NULL, NULL, NULL),
        WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_X509_get_signature(x509, NULL, NULL),
        WOLFSSL_FATAL_ERROR);
    ExpectIntEQ(wolfSSL_X509_get_signature(NULL, NULL, &sigSz),
        WOLFSSL_FATAL_ERROR);
    sigSz = 0;
    ExpectIntEQ(wolfSSL_X509_get_signature(x509, sn, &sigSz),
        WOLFSSL_FATAL_ERROR);

    /* test valid X509_sign_ctx case */
    ExpectNotNull(mctx = EVP_MD_CTX_new());
    ExpectIntEQ(EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, priv), 1);
    ExpectIntGT(X509_sign_ctx(x509, mctx), 0);

#if defined(OPENSSL_ALL) && defined(WOLFSSL_ALT_NAMES)
    ExpectIntEQ(X509_get_ext_count(x509), 1);
#endif
#if defined(WOLFSSL_ALT_NAMES) && defined(WOLFSSL_IP_ALT_NAME)
    ExpectIntEQ(wolfSSL_X509_check_ip_asc(x509, "127.128.0.255", 0), 1);
    ExpectIntEQ(wolfSSL_X509_check_ip_asc(x509,
        "DDCC:BAAB:FFEE:9988:7766:5544:0033:2211", 0), 1);
#endif

    ExpectIntEQ(wolfSSL_X509_get_serial_number(x509, sn, &snSz),
                WOLFSSL_SUCCESS);
    DEBUG_WRITE_CERT_X509(x509, "signed.pem");

    /* Variation in size depends on ASN.1 encoding when MSB is set.
     * WOLFSSL_ASN_TEMPLATE code does not generate a serial number
     * with the MSB set. See GenerateInteger in asn.c */
#ifndef USE_CERT_BUFFERS_1024
#ifndef WOLFSSL_ALT_NAMES
    /* Valid case - size should be 781-786 with 16 byte serial number */
    ExpectTrue((781 + snSz <= ret) && (ret <= 781 + 5 + snSz));
#elif defined(WOLFSSL_IP_ALT_NAME)
    /* Valid case - size should be 955-960 with 16 byte serial number */
    ExpectTrue((939 + snSz <= ret) && (ret <= 939 + 5 + snSz));
#else
    /* Valid case - size should be 926-931 with 16 byte serial number */
    ExpectTrue((910 + snSz <= ret) && (ret <= 910 + 5 + snSz));
#endif
#else
#ifndef WOLFSSL_ALT_NAMES
    /* Valid case - size should be 537-542 with 16 byte serial number */
    ExpectTrue((521 + snSz <= ret) && (ret <= 521 + 5 + snSz));
#elif defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME)
    /* Valid case - size should be 695-670 with 16 byte serial number */
    ExpectTrue((679 + snSz <= ret) && (ret <= 679 + 5 + snSz));
#else
    /* Valid case - size should be 666-671 with 16 byte serial number */
    ExpectTrue((650 + snSz <= ret) && (ret <= 650 + 5 + snSz));
#endif
#endif
    /* check that issuer name is as expected after signature */
    InitDecodedCert(&dCert, certIssuer, (word32)certIssuerSz, 0);
    ExpectIntEQ(ParseCert(&dCert, CERT_TYPE, NO_VERIFY, NULL), 0);

    ExpectNotNull(emptyName = X509_NAME_new());
    ExpectNotNull(ca = d2i_X509(NULL, &certIssuer, (int)certIssuerSz));
    ExpectIntEQ(wolfSSL_X509_get_isCA(NULL), 0);
    ExpectIntEQ(wolfSSL_X509_get_isCA(ca), 1);
    ExpectNotNull(name = X509_get_subject_name(ca));
    ExpectIntEQ(X509_NAME_get_sz(NULL), WOLFSSL_FATAL_ERROR);
    ExpectIntGT(cnSz = X509_NAME_get_sz(name), 0);
    ExpectNotNull(cn = (char*)XMALLOC(cnSz, HEAP_HINT, DYNAMIC_TYPE_OPENSSL));
    ExpectNull(X509_NAME_oneline(NULL, cn, (int)cnSz));
    ExpectPtrEq(X509_NAME_oneline(name, cn, 0), cn);
    ExpectPtrEq(X509_NAME_oneline(emptyName, cn, (int)cnSz), cn);
    ExpectNull(X509_NAME_oneline(emptyName, NULL, 0));
    ExpectPtrEq(X509_NAME_oneline(name, cn, (int)cnSz), cn);
    ExpectIntEQ(0, XSTRNCMP(cn, dCert.subject, XSTRLEN(cn)));
    XFREE(cn, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
    cn = NULL;

#if defined(XSNPRINTF)
    ExpectNull(wolfSSL_X509_get_name_oneline(NULL, NULL, 0));
    ExpectNotNull(cn = wolfSSL_X509_get_name_oneline(name, NULL, 0));
    ExpectIntGT((int)(cnSz = (word32)XSTRLEN(cn) + 1), 0);
    ExpectPtrEq(wolfSSL_X509_get_name_oneline(name, cn, (int)cnSz), cn);
    ExpectNull(wolfSSL_X509_get_name_oneline(NULL, cn, (int)cnSz));
    ExpectNull(wolfSSL_X509_get_name_oneline(name, cn, cnSz - 1));
    ExpectPtrEq(wolfSSL_X509_get_name_oneline(name, cn, (int)cnSz), cn);
    ExpectPtrEq(wolfSSL_X509_get_name_oneline(emptyName, cn, (int)cnSz), cn);
    XFREE(cn, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
    cn = NULL;
#endif
    X509_NAME_free(emptyName);

#ifdef WOLFSSL_MULTI_ATTRIB
    /* test adding multiple OU's to the signer */
    ExpectNotNull(name = X509_get_subject_name(ca));
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_UTF8,
                                       (byte*)"OU1", 3, -1, 0), SSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_UTF8,
                                       (byte*)"OU2", 3, -1, 0), SSL_SUCCESS);
    ExpectIntGT(X509_sign(ca, priv, EVP_sha256()), 0);
#endif

    ExpectNotNull(name = X509_get_subject_name(ca));
    ExpectIntEQ(X509_set_issuer_name(x509, name), SSL_SUCCESS);

    ExpectIntGT(X509_sign(x509, priv, EVP_sha256()), 0);
    ExpectNotNull(name = X509_get_issuer_name(x509));
    cnSz = X509_NAME_get_sz(name);
    ExpectNotNull(cn = (char*)XMALLOC(cnSz, HEAP_HINT, DYNAMIC_TYPE_OPENSSL));
    ExpectNotNull(cn = X509_NAME_oneline(name, cn, (int)cnSz));
    /* compare and don't include the multi-attrib "/OU=OU1/OU=OU2" above */
    ExpectIntEQ(0, XSTRNCMP(cn, dCert.issuer, XSTRLEN(dCert.issuer)));
    XFREE(cn, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
    cn = NULL;

    FreeDecodedCert(&dCert);

    /* Test invalid parameters */
    ExpectIntEQ(X509_sign(NULL, priv, EVP_sha256()), 0);
    ExpectIntEQ(X509_sign(x509, NULL, EVP_sha256()), 0);
    ExpectIntEQ(X509_sign(x509, priv, NULL), 0);

    ExpectIntEQ(X509_sign_ctx(NULL, mctx), 0);
    EVP_MD_CTX_free(mctx);
    mctx = NULL;
    ExpectNotNull(mctx = EVP_MD_CTX_new());
    ExpectIntEQ(X509_sign_ctx(x509, mctx), 0);
    ExpectIntEQ(X509_sign_ctx(x509, NULL), 0);

    /* test invalid version number */
#if defined(OPENSSL_ALL)
    ExpectIntNE(X509_set_version(x509, 6L), 0);
    ExpectIntGT(X509_sign(x509, priv, EVP_sha256()), 0);

    /* uses ParseCert which fails on bad version number */
    ExpectIntEQ(X509_get_ext_count(x509), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif

    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    X509_free(x509);
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_sign2(void)
{
    EXPECT_DECLS;
    /* test requires WOLFSSL_AKID_NAME to match expected output */
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) && !defined(NO_CERTS) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_ALT_NAMES) && \
    defined(WOLFSSL_CERT_EXT) && defined(WOLFSSL_AKID_NAME) && \
    (defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || \
    defined(WOLFSSL_IP_ALT_NAME))
    WOLFSSL_X509 *x509 = NULL;
    WOLFSSL_X509 *ca = NULL;
    const unsigned char *der = NULL;
    const unsigned char *pt = NULL;
    WOLFSSL_EVP_PKEY  *priv = NULL;
    WOLFSSL_X509_NAME *name = NULL;
    int derSz;
#ifndef NO_ASN_TIME
    WOLFSSL_ASN1_TIME *notBefore = NULL;
    WOLFSSL_ASN1_TIME *notAfter = NULL;

    const int year = 365*24*60*60;
    const int day  = 24*60*60;
    const int hour = 60*60;
    const int mini = 60;
    time_t t;
#endif

    const unsigned char expected[] = {
        0x30, 0x82, 0x05, 0x13, 0x30, 0x82, 0x03, 0xFB, 0xA0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x6B, 0x61, 0x49, 0x45, 0xFF, 0x4A, 0xD1, 0x54, 0x16,
        0xB4, 0x35, 0x37, 0xC4, 0x98, 0x5D, 0xA9, 0xF6, 0x67, 0x60, 0x91, 0x30,
        0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        0x05, 0x00, 0x30, 0x81, 0x94, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55,
        0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03,
        0x55, 0x04, 0x08, 0x0C, 0x07, 0x4D, 0x6F, 0x6E, 0x74, 0x61, 0x6E, 0x61,
        0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42,
        0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03,
        0x55, 0x04, 0x0A, 0x0C, 0x08, 0x53, 0x61, 0x77, 0x74, 0x6F, 0x6F, 0x74,
        0x68, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0A,
        0x43, 0x6F, 0x6E, 0x73, 0x75, 0x6C, 0x74, 0x69, 0x6E, 0x67, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x77, 0x77, 0x77,
        0x2E, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D,
        0x31, 0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
        0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40, 0x77, 0x6F,
        0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x1E, 0x17,
        0x0D, 0x30, 0x30, 0x30, 0x32, 0x31, 0x35, 0x32, 0x30, 0x33, 0x30, 0x30,
        0x30, 0x5A, 0x17, 0x0D, 0x30, 0x31, 0x30, 0x32, 0x31, 0x34, 0x32, 0x30,
        0x33, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x81, 0x9E, 0x31, 0x0B, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30,
        0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x07, 0x4D, 0x6F, 0x6E, 0x74,
        0x61, 0x6E, 0x61, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07,
        0x0C, 0x07, 0x42, 0x6F, 0x7A, 0x65, 0x6D, 0x61, 0x6E, 0x31, 0x15, 0x30,
        0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0C, 0x77, 0x6F, 0x6C, 0x66,
        0x53, 0x53, 0x4C, 0x5F, 0x32, 0x30, 0x34, 0x38, 0x31, 0x19, 0x30, 0x17,
        0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x10, 0x50, 0x72, 0x6F, 0x67, 0x72,
        0x61, 0x6D, 0x6D, 0x69, 0x6E, 0x67, 0x2D, 0x32, 0x30, 0x34, 0x38, 0x31,
        0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x77, 0x77,
        0x77, 0x2E, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F,
        0x6D, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
        0x0D, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E, 0x66, 0x6F, 0x40, 0x77,
        0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x82,
        0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
        0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82,
        0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xC3, 0x03, 0xD1, 0x2B, 0xFE,
        0x39, 0xA4, 0x32, 0x45, 0x3B, 0x53, 0xC8, 0x84, 0x2B, 0x2A, 0x7C, 0x74,
        0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07, 0x47, 0xD6, 0xA6, 0x36, 0xB2, 0x07,
        0x32, 0x8E, 0xD0, 0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E, 0xD4, 0x81,
        0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B, 0x67, 0xBB, 0xA1, 0x75, 0xC8, 0x36,
        0x2C, 0x4A, 0xD2, 0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9, 0xEF, 0xEC,
        0xF1, 0x81, 0x1E, 0x7B, 0x9B, 0x03, 0x47, 0x9A, 0xBF, 0x65, 0xCC, 0x7F,
        0x65, 0x24, 0x69, 0xA6, 0xE8, 0x14, 0x89, 0x5B, 0xE4, 0x34, 0xF7, 0xC5,
        0xB0, 0x14, 0x93, 0xF5, 0x67, 0x7B, 0x3A, 0x7A, 0x78, 0xE1, 0x01, 0x56,
        0x56, 0x91, 0xA6, 0x13, 0x42, 0x8D, 0xD2, 0x3C, 0x40, 0x9C, 0x4C, 0xEF,
        0xD1, 0x86, 0xDF, 0x37, 0x51, 0x1B, 0x0C, 0xA1, 0x3B, 0xF5, 0xF1, 0xA3,
        0x4A, 0x35, 0xE4, 0xE1, 0xCE, 0x96, 0xDF, 0x1B, 0x7E, 0xBF, 0x4E, 0x97,
        0xD0, 0x10, 0xE8, 0xA8, 0x08, 0x30, 0x81, 0xAF, 0x20, 0x0B, 0x43, 0x14,
        0xC5, 0x74, 0x67, 0xB4, 0x32, 0x82, 0x6F, 0x8D, 0x86, 0xC2, 0x88, 0x40,
        0x99, 0x36, 0x83, 0xBA, 0x1E, 0x40, 0x72, 0x22, 0x17, 0xD7, 0x52, 0x65,
        0x24, 0x73, 0xB0, 0xCE, 0xEF, 0x19, 0xCD, 0xAE, 0xFF, 0x78, 0x6C, 0x7B,
        0xC0, 0x12, 0x03, 0xD4, 0x4E, 0x72, 0x0D, 0x50, 0x6D, 0x3B, 0xA3, 0x3B,
        0xA3, 0x99, 0x5E, 0x9D, 0xC8, 0xD9, 0x0C, 0x85, 0xB3, 0xD9, 0x8A, 0xD9,
        0x54, 0x26, 0xDB, 0x6D, 0xFA, 0xAC, 0xBB, 0xFF, 0x25, 0x4C, 0xC4, 0xD1,
        0x79, 0xF4, 0x71, 0xD3, 0x86, 0x40, 0x18, 0x13, 0xB0, 0x63, 0xB5, 0x72,
        0x4E, 0x30, 0xC4, 0x97, 0x84, 0x86, 0x2D, 0x56, 0x2F, 0xD7, 0x15, 0xF7,
        0x7F, 0xC0, 0xAE, 0xF5, 0xFC, 0x5B, 0xE5, 0xFB, 0xA1, 0xBA, 0xD3, 0x02,
        0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x01, 0x4F, 0x30, 0x82, 0x01, 0x4B,
        0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01,
        0x01, 0xFF, 0x30, 0x1C, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x15, 0x30,
        0x13, 0x82, 0x0B, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63,
        0x6F, 0x6D, 0x87, 0x04, 0x7F, 0x00, 0x00, 0x01, 0x30, 0x1D, 0x06, 0x03,
        0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x33, 0xD8, 0x45, 0x66, 0xD7,
        0x68, 0x87, 0x18, 0x7E, 0x54, 0x0D, 0x70, 0x27, 0x91, 0xC7, 0x26, 0xD7,
        0x85, 0x65, 0xC0, 0x30, 0x81, 0xDE, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04,
        0x81, 0xD6, 0x30, 0x81, 0xD3, 0x80, 0x14, 0x33, 0xD8, 0x45, 0x66, 0xD7,
        0x68, 0x87, 0x18, 0x7E, 0x54, 0x0D, 0x70, 0x27, 0x91, 0xC7, 0x26, 0xD7,
        0x85, 0x65, 0xC0, 0xA1, 0x81, 0xA4, 0xA4, 0x81, 0xA1, 0x30, 0x81, 0x9E,
        0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
        0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x07,
        0x4D, 0x6F, 0x6E, 0x74, 0x61, 0x6E, 0x61, 0x31, 0x10, 0x30, 0x0E, 0x06,
        0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x42, 0x6F, 0x7A, 0x65, 0x6D, 0x61,
        0x6E, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0C,
        0x77, 0x6F, 0x6C, 0x66, 0x53, 0x53, 0x4C, 0x5F, 0x32, 0x30, 0x34, 0x38,
        0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x10, 0x50,
        0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x6D, 0x69, 0x6E, 0x67, 0x2D, 0x32,
        0x30, 0x34, 0x38, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0C, 0x0F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73,
        0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x10, 0x69, 0x6E,
        0x66, 0x6F, 0x40, 0x77, 0x6F, 0x6C, 0x66, 0x73, 0x73, 0x6C, 0x2E, 0x63,
        0x6F, 0x6D, 0x82, 0x14, 0x6B, 0x61, 0x49, 0x45, 0xFF, 0x4A, 0xD1, 0x54,
        0x16, 0xB4, 0x35, 0x37, 0xC4, 0x98, 0x5D, 0xA9, 0xF6, 0x67, 0x60, 0x91,
        0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06,
        0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A,
        0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82,
        0x01, 0x01, 0x00, 0x2F, 0x9F, 0x83, 0x05, 0x15, 0x1E, 0x5D, 0x7C, 0x22,
        0x12, 0x20, 0xEE, 0x07, 0x35, 0x25, 0x39, 0xDD, 0x34, 0x06, 0xD3, 0x89,
        0x31, 0x51, 0x8B, 0x9A, 0xE5, 0xE8, 0x60, 0x30, 0x07, 0x7A, 0xBB, 0x17,
        0xB9, 0x54, 0x72, 0x83, 0xA2, 0x1F, 0x62, 0xE0, 0x18, 0xAC, 0x93, 0x5E,
        0x63, 0xC7, 0xDD, 0x12, 0x58, 0x96, 0xC7, 0x90, 0x8B, 0x12, 0x50, 0xD2,
        0x60, 0x0E, 0x24, 0x07, 0x53, 0x55, 0xD7, 0x8E, 0xC9, 0x56, 0x12, 0x28,
        0xD8, 0xFD, 0x47, 0xE3, 0x13, 0xFB, 0x3C, 0xD6, 0x3D, 0x82, 0x09, 0x7E,
        0x10, 0x19, 0xE1, 0xCD, 0xCC, 0x4C, 0x78, 0xDF, 0xE5, 0xFB, 0x2C, 0x8C,
        0x88, 0xF7, 0x5B, 0x99, 0x93, 0xC6, 0xC7, 0x22, 0xA5, 0xFA, 0x76, 0x6C,
        0xE9, 0xBC, 0x69, 0xBA, 0x02, 0x82, 0x18, 0xAF, 0x47, 0xD0, 0x9C, 0x5F,
        0xED, 0xAE, 0x5A, 0x95, 0x59, 0x78, 0x86, 0x24, 0x22, 0xB6, 0x81, 0x03,
        0x58, 0x9A, 0x14, 0x93, 0xDC, 0x24, 0x58, 0xF3, 0xD2, 0x6C, 0x8E, 0xD2,
        0x6D, 0x8B, 0xE8, 0x4E, 0xC6, 0xA0, 0x2B, 0x0D, 0xDB, 0x1A, 0x76, 0x28,
        0xA9, 0x8D, 0xFB, 0x51, 0xA6, 0xF0, 0x82, 0x30, 0xEE, 0x78, 0x1C, 0x71,
        0xA8, 0x11, 0x8A, 0xA5, 0xC3, 0x91, 0xAB, 0x9A, 0x46, 0xFF, 0x8D, 0xCD,
        0x82, 0x3F, 0x5D, 0xB6, 0x28, 0x46, 0x6D, 0x66, 0xE2, 0xEE, 0x1E, 0x82,
        0x0D, 0x1A, 0x74, 0x87, 0xFB, 0xFD, 0x96, 0x26, 0x50, 0x09, 0xEC, 0xA7,
        0x73, 0x89, 0x43, 0x3B, 0x42, 0x2D, 0xA9, 0x6B, 0x0F, 0x61, 0x81, 0x97,
        0x11, 0x71, 0xF9, 0xDB, 0x9B, 0x69, 0x4B, 0x6E, 0xD3, 0x7D, 0xDA, 0xC6,
        0x61, 0x9F, 0x39, 0x87, 0x53, 0x52, 0xA8, 0x4D, 0xAD, 0x80, 0x29, 0x6C,
        0x19, 0xF0, 0x8D, 0xB1, 0x0D, 0x4E, 0xFB, 0x1B, 0xB7, 0xF1, 0x85, 0x49,
        0x08, 0x2A, 0x94, 0xD0, 0x4E, 0x0B, 0x8F
    };

    pt = ca_key_der_2048;
    ExpectNotNull(priv = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL, &pt,
        sizeof_ca_key_der_2048));

    pt = client_cert_der_2048;
    ExpectNotNull(x509 = wolfSSL_d2i_X509(NULL, &pt,
        sizeof_client_cert_der_2048));

    pt = ca_cert_der_2048;
    ExpectNotNull(ca = wolfSSL_d2i_X509(NULL, &pt, sizeof_ca_cert_der_2048));
    ExpectNotNull(name = wolfSSL_X509_get_subject_name(ca));
    ExpectIntEQ(wolfSSL_X509_set_issuer_name(x509, name), WOLFSSL_SUCCESS);

#ifndef NO_ASN_TIME
    t = (time_t)30 * year + 45 * day + 20 * hour + 30 * mini + 7 * day;
    ExpectNotNull(notBefore = wolfSSL_ASN1_TIME_adj(NULL, t, 0, 0));
    ExpectNotNull(notAfter = wolfSSL_ASN1_TIME_adj(NULL, t, 365, 0));
    ExpectIntEQ(notAfter->length, 13);

    ExpectTrue(wolfSSL_X509_set_notBefore(x509, notBefore));
    ExpectTrue(wolfSSL_X509_set1_notBefore(x509, notBefore));
    ExpectTrue(wolfSSL_X509_set_notAfter(x509, notAfter));
    ExpectTrue(wolfSSL_X509_set1_notAfter(x509, notAfter));
#endif

    ExpectNull(wolfSSL_X509_notBefore(NULL));
    ExpectNotNull(wolfSSL_X509_notBefore(x509));
    ExpectNull(wolfSSL_X509_notAfter(NULL));
    ExpectNotNull(wolfSSL_X509_notAfter(x509));

    ExpectIntGT(wolfSSL_X509_sign(x509, priv, EVP_sha256()), 0);
    ExpectNotNull((der = wolfSSL_X509_get_der(x509, &derSz)));

    ExpectIntEQ(derSz, sizeof(expected));
#ifndef NO_ASN_TIME
    ExpectIntEQ(XMEMCMP(der, expected, derSz), 0);
#endif
    wolfSSL_X509_free(ca);
    wolfSSL_X509_free(x509);
    wolfSSL_EVP_PKEY_free(priv);
#ifndef NO_ASN_TIME
    wolfSSL_ASN1_TIME_free(notBefore);
    wolfSSL_ASN1_TIME_free(notAfter);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_make_cert(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && !defined(NO_ASN_TIME) && defined(WOLFSSL_CERT_GEN) && \
    defined(WOLFSSL_CERT_EXT)
    int      ret = 0;
    Cert     cert;
    CertName name;
    RsaKey   key;
    WC_RNG   rng;
    byte     der[FOURK_BUF];
    word32   idx = 0;
    const byte mySerial[8] = {1,2,3,4,5,6,7,8};

#ifdef OPENSSL_EXTRA
    const unsigned char* pt = NULL;
    int                  certSz = 0;
    X509*                x509 = NULL;
    X509_NAME*           x509name = NULL;
    X509_NAME_ENTRY*     entry = NULL;
    ASN1_STRING*         entryValue = NULL;
#endif

    XMEMSET(&name, 0, sizeof(CertName));

    /* set up cert name */
    XMEMCPY(name.country, "US", sizeof("US"));
    name.countryEnc = CTC_PRINTABLE;
    XMEMCPY(name.state, "Oregon", sizeof("Oregon"));
    name.stateEnc = CTC_UTF8;
    XMEMCPY(name.locality, "Portland", sizeof("Portland"));
    name.localityEnc = CTC_UTF8;
    XMEMCPY(name.sur, "Test", sizeof("Test"));
    name.surEnc = CTC_UTF8;
    XMEMCPY(name.org, "wolfSSL", sizeof("wolfSSL"));
    name.orgEnc = CTC_UTF8;
    XMEMCPY(name.unit, "Development", sizeof("Development"));
    name.unitEnc = CTC_UTF8;
    XMEMCPY(name.commonName, "www.wolfssl.com", sizeof("www.wolfssl.com"));
    name.commonNameEnc = CTC_UTF8;
    XMEMCPY(name.serialDev, "wolfSSL12345", sizeof("wolfSSL12345"));
    name.serialDevEnc = CTC_PRINTABLE;
    XMEMCPY(name.userId, "TestUserID", sizeof("TestUserID"));
    name.userIdEnc = CTC_PRINTABLE;
#ifdef WOLFSSL_MULTI_ATTRIB
    #if CTC_MAX_ATTRIB > 2
    {
        NameAttrib* n;
        n = &name.name[0];
        n->id   = ASN_DOMAIN_COMPONENT;
        n->type = CTC_UTF8;
        n->sz   = sizeof("com");
        XMEMCPY(n->value, "com", sizeof("com"));

        n = &name.name[1];
        n->id   = ASN_DOMAIN_COMPONENT;
        n->type = CTC_UTF8;
        n->sz   = sizeof("wolfssl");
        XMEMCPY(n->value, "wolfssl", sizeof("wolfssl"));
    }
    #endif
#endif /* WOLFSSL_MULTI_ATTRIB */

    ExpectIntEQ(wc_InitRsaKey(&key, HEAP_HINT), 0);
#ifndef HAVE_FIPS
    ExpectIntEQ(wc_InitRng_ex(&rng, HEAP_HINT, testDevId), 0);
#else
    ExpectIntEQ(wc_InitRng(&rng), 0);
#endif

    /* load test RSA key */
    idx = 0;
#if defined(USE_CERT_BUFFERS_1024)
    ExpectIntEQ(wc_RsaPrivateKeyDecode(server_key_der_1024, &idx, &key,
                sizeof_server_key_der_1024), 0);
#elif defined(USE_CERT_BUFFERS_2048)
    ExpectIntEQ(wc_RsaPrivateKeyDecode(server_key_der_2048, &idx, &key,
                sizeof_server_key_der_2048), 0);
#else
    /* error case, no RSA key loaded, happens later */
    (void)idx;
#endif

    XMEMSET(&cert, 0 , sizeof(Cert));
    ExpectIntEQ(wc_InitCert(&cert), 0);

    XMEMCPY(&cert.subject, &name, sizeof(CertName));
    XMEMCPY(cert.serial, mySerial, sizeof(mySerial));
    cert.serialSz = (int)sizeof(mySerial);
    cert.isCA     = 1;
#ifndef NO_SHA256
    cert.sigType = CTC_SHA256wRSA;
#else
    cert.sigType = CTC_SHAwRSA;
#endif

    /* add SKID from the Public Key */
    ExpectIntEQ(wc_SetSubjectKeyIdFromPublicKey(&cert, &key, NULL), 0);

    /* add AKID from the Public Key */
    ExpectIntEQ(wc_SetAuthKeyIdFromPublicKey(&cert, &key, NULL), 0);

    ret = 0;
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_MakeSelfCert(&cert, der, FOURK_BUF, &key, &rng);
        }
    } while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    ExpectIntGT(ret, 0);

#ifdef OPENSSL_EXTRA
    /* der holds a certificate with DC's now check X509 parsing of it */
    certSz = ret;
    pt = der;
    ExpectNotNull(x509 = d2i_X509(NULL, &pt, certSz));
    ExpectNotNull(x509name = X509_get_subject_name(x509));
#ifdef WOLFSSL_MULTI_ATTRIB
    ExpectIntEQ((idx = X509_NAME_get_index_by_NID(x509name, NID_domainComponent,
                    -1)), 5);
    ExpectIntEQ((idx = X509_NAME_get_index_by_NID(x509name, NID_domainComponent,
                    (int)idx)), 6);
    ExpectIntEQ((idx = X509_NAME_get_index_by_NID(x509name, NID_domainComponent,
                    (int)idx)), -1);
#endif /* WOLFSSL_MULTI_ATTRIB */

    /* compare DN at index 0 */
    ExpectNotNull(entry = X509_NAME_get_entry(x509name, 0));
    ExpectNotNull(entryValue = X509_NAME_ENTRY_get_data(entry));
    ExpectIntEQ(ASN1_STRING_length(entryValue), 2);
    ExpectStrEQ((const char*)ASN1_STRING_data(entryValue), "US");

#ifndef WOLFSSL_MULTI_ATTRIB
    /* compare Serial Number */
    ExpectIntEQ((idx = X509_NAME_get_index_by_NID(x509name, NID_serialNumber,
                    -1)), 7);
    ExpectNotNull(entry = X509_NAME_get_entry(x509name, idx));
    ExpectNotNull(entryValue = X509_NAME_ENTRY_get_data(entry));
    ExpectIntEQ(ASN1_STRING_length(entryValue), XSTRLEN("wolfSSL12345"));
    ExpectStrEQ((const char*)ASN1_STRING_data(entryValue), "wolfSSL12345");
#endif

#ifdef WOLFSSL_MULTI_ATTRIB
    /* get first and second DC and compare result */
    ExpectIntEQ((idx = X509_NAME_get_index_by_NID(x509name, NID_domainComponent,
                    -1)), 5);
    ExpectNotNull(entry = X509_NAME_get_entry(x509name, (int)idx));
    ExpectNotNull(entryValue = X509_NAME_ENTRY_get_data(entry));
    ExpectStrEQ((const char *)ASN1_STRING_data(entryValue), "com");

    ExpectIntEQ((idx = X509_NAME_get_index_by_NID(x509name, NID_domainComponent,
                   (int)idx)), 6);
    ExpectNotNull(entry = X509_NAME_get_entry(x509name, (int)idx));
    ExpectNotNull(entryValue = X509_NAME_ENTRY_get_data(entry));
    ExpectStrEQ((const char *)ASN1_STRING_data(entryValue), "wolfssl");
#endif /* WOLFSSL_MULTI_ATTRIB */

    ExpectNull(X509_NAME_get_entry(NULL, 0));
    /* try invalid index locations for regression test and sanity check */
    ExpectNull(X509_NAME_get_entry(x509name, 11));
    ExpectNull(X509_NAME_get_entry(x509name, 20));

    X509_free(x509);
#endif /* OPENSSL_EXTRA */

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
#endif
    return EXPECT_RESULT();
}


