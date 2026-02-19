/* test_ossl_pem.c
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
#include <wolfssl/openssl/buffer.h>
#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/pem.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_ossl_pem.h>


int test_wolfSSL_PEM_def_callback(void)
{
    EXPECT_DECLS;
#ifdef OPENSSL_EXTRA
    char buf[10];
    const char* defpwd = "DEF PWD";
    int defpwdLen = (int)XSTRLEN(defpwd);
    int smallLen = 1;

    /* Bad parameters. */
    ExpectIntEQ(wolfSSL_PEM_def_callback(NULL, sizeof(buf), 0, NULL), 0);
    ExpectIntEQ(wolfSSL_PEM_def_callback(NULL, sizeof(buf), 0, (void*)defpwd),
        0);
    ExpectIntEQ(wolfSSL_PEM_def_callback(buf, sizeof(buf), 0, NULL), 0);

    XMEMSET(buf, 0, sizeof(buf));
    ExpectIntEQ(wolfSSL_PEM_def_callback(buf, sizeof(buf), 0, (void*)defpwd),
        defpwdLen);
    ExpectIntEQ(XMEMCMP(buf, defpwd, defpwdLen), 0);
    ExpectIntEQ(buf[defpwdLen], 0);
    /* Size of buffer is smaller than default password. */
    XMEMSET(buf, 0, sizeof(buf));
    ExpectIntEQ(wolfSSL_PEM_def_callback(buf, smallLen, 0, (void*)defpwd),
        smallLen);
    ExpectIntEQ(XMEMCMP(buf, defpwd, smallLen), 0);
    ExpectIntEQ(buf[smallLen], 0);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_read_PrivateKey(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && (!defined(NO_RSA) || \
    !defined(NO_DSA) || defined(HAVE_ECC) || !defined(NO_DH))
    XFILE file = XBADFILE;
#if !defined(NO_RSA)
    const char* fname_rsa = "./certs/server-key.pem";
    RSA* rsa = NULL;
    WOLFSSL_EVP_PKEY_CTX* ctx = NULL;
    unsigned char* sig = NULL;
    size_t sigLen = 0;
    const unsigned char tbs[] = {0, 1, 2, 3, 4, 5, 6, 7};
    size_t tbsLen = sizeof(tbs);
#endif
#if !defined(NO_DSA)
    const char* fname_dsa = "./certs/dsa2048.pem";
#endif
#if defined(HAVE_ECC)
    const char* fname_ec = "./certs/ecc-key.pem";
#endif
#if !defined(NO_DH)
    const char* fname_dh = "./certs/dh-priv-2048.pem";
#endif
    EVP_PKEY* pkey = NULL;

    /* Check error case. */
    ExpectNull(pkey = PEM_read_PrivateKey(NULL, NULL, NULL, NULL));

    /* not a PEM key. */
    ExpectTrue((file = XFOPEN("./certs/ecc-key.der", "rb")) != XBADFILE);
    ExpectNull(PEM_read_PrivateKey(file, NULL, NULL, NULL));
    if (file != XBADFILE)
        XFCLOSE(file);
    file = XBADFILE;

#ifndef NO_RSA
    /* Read in an RSA key. */
    ExpectTrue((file = XFOPEN(fname_rsa, "rb")) != XBADFILE);
    ExpectNotNull(pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL));
    if (file != XBADFILE)
        XFCLOSE(file);
    file = XBADFILE;

    /* Make sure the key is usable by signing some data with it. */
    ExpectNotNull(rsa = EVP_PKEY_get0_RSA(pkey));
    ExpectIntGT((sigLen = RSA_size(rsa)), 0);
    ExpectNotNull(sig = (unsigned char*)XMALLOC(sigLen, HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));
    ExpectNotNull(ctx = EVP_PKEY_CTX_new(pkey, NULL));
    ExpectIntEQ(EVP_PKEY_sign_init(ctx), WOLFSSL_SUCCESS);
    ExpectIntEQ(EVP_PKEY_sign(ctx, sig, &sigLen, tbs, tbsLen),
        WOLFSSL_SUCCESS);

    XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    pkey = NULL;
#endif

#ifndef NO_DSA
    /* Read in a DSA key. */
    ExpectTrue((file = XFOPEN(fname_dsa, "rb")) != XBADFILE);
#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || defined(WOLFSSL_OPENSSH)
    ExpectNotNull(pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL));
    EVP_PKEY_free(pkey);
    pkey = NULL;
#else
    ExpectNull(PEM_read_PrivateKey(file, NULL, NULL, NULL));
#endif
    if (file != XBADFILE)
        XFCLOSE(file);
    file = XBADFILE;
#endif

#ifdef HAVE_ECC
    /* Read in an EC key. */
    ExpectTrue((file = XFOPEN(fname_ec, "rb")) != XBADFILE);
    ExpectNotNull(pkey = EVP_PKEY_new());
    ExpectPtrEq(PEM_read_PrivateKey(file, &pkey, NULL, NULL), pkey);
    if (file != XBADFILE)
        XFCLOSE(file);
    file = XBADFILE;
    EVP_PKEY_free(pkey);
    pkey = NULL;
#endif

#ifndef NO_DH
    /* Read in a DH key. */
    ExpectTrue((file = XFOPEN(fname_dh, "rb")) != XBADFILE);
#if (defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || \
     defined(WOLFSSL_OPENSSH)) && (!defined(HAVE_FIPS) || \
     (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
    ExpectNotNull(pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL));
    EVP_PKEY_free(pkey);
    pkey = NULL;
#else
    ExpectNull(PEM_read_PrivateKey(file, NULL, NULL, NULL));
#endif
    if (file != XBADFILE)
        XFCLOSE(file);
    file = XBADFILE;
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_read_PUBKEY(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_RSA) \
    && !defined(NO_FILESYSTEM)
    XFILE file = XBADFILE;
    const char* fname = "./certs/client-keyPub.pem";
    EVP_PKEY* pkey = NULL;

    /* Check error case. */
    ExpectNull(pkey = PEM_read_PUBKEY(NULL, NULL, NULL, NULL));

    /* Read in an RSA key. */
    ExpectTrue((file = XFOPEN(fname, "rb")) != XBADFILE);
    ExpectNotNull(pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL));
    EVP_PKEY_free(pkey);
    pkey = NULL;
    if (file != XBADFILE)
        XFCLOSE(file);
    file = XBADFILE;
    ExpectTrue((file = XFOPEN(fname, "rb")) != XBADFILE);
    ExpectNotNull(pkey = EVP_PKEY_new());
    ExpectPtrEq(PEM_read_PUBKEY(file, &pkey, NULL, NULL), pkey);
    EVP_PKEY_free(pkey);
    if (file != XBADFILE)
        XFCLOSE(file);
#endif
    return EXPECT_RESULT();
}

/* test loading RSA key using BIO */
int test_wolfSSL_PEM_PrivateKey_rsa(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_RSA) && \
    defined(USE_CERT_BUFFERS_2048) && !defined(NO_FILESYSTEM) && \
    !defined(NO_BIO)
    BIO*      bio = NULL;
    XFILE file = XBADFILE;
    const char* fname = "./certs/server-key.pem";
    const char* fname_rsa_p8 = "./certs/server-keyPkcs8.pem";
    EVP_PKEY* pkey  = NULL;
    size_t sz = 0;
    byte* buf = NULL;
    EVP_PKEY* pkey2 = NULL;
    EVP_PKEY* pkey3 = NULL;
    RSA* rsa_key = NULL;
#if defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_CERT_GEN)
    unsigned char extra[10];
    int i;
    BIO* pub_bio = NULL;
    const unsigned char* server_key = (const unsigned char*)server_key_der_2048;
#endif

    ExpectTrue((file = XFOPEN(fname, "rb")) != XBADFILE);
    ExpectTrue(XFSEEK(file, 0, XSEEK_END) == 0);
    ExpectIntGT(sz = XFTELL(file), 0);
    ExpectTrue(XFSEEK(file, 0, XSEEK_SET) == 0);
    ExpectNotNull(buf = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE));
    if (buf != NULL) {
        ExpectIntEQ(XFREAD(buf, 1, sz, file), sz);
    }
    if (file != XBADFILE) {
        XFCLOSE(file);
        file = XBADFILE;
    }

    /* Test using BIO new mem and loading PEM private key */
    ExpectNotNull(bio = BIO_new_mem_buf(buf, (int)sz));
    ExpectNotNull((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)));
    XFREE(buf, NULL, DYNAMIC_TYPE_FILE);
    buf = NULL;
    BIO_free(bio);
    bio = NULL;

    /* New empty EVP_PKEY */
    ExpectNotNull(pkey2 = EVP_PKEY_new());
    if (pkey2 != NULL) {
        pkey2->type = EVP_PKEY_RSA;
    }
    /* Test parameter copy */
    ExpectIntEQ(EVP_PKEY_copy_parameters(pkey2, pkey), 0);
    EVP_PKEY_free(pkey2);
    EVP_PKEY_free(pkey);
    pkey  = NULL;

    /* Qt unit test case : rsa pkcs8 key */
    ExpectTrue((file = XFOPEN(fname_rsa_p8, "rb")) != XBADFILE);
    ExpectTrue(XFSEEK(file, 0, XSEEK_END) == 0);
    ExpectIntGT(sz = XFTELL(file), 0);
    ExpectTrue(XFSEEK(file, 0, XSEEK_SET) == 0);
    ExpectNotNull(buf = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE));
    if (buf) {
        ExpectIntEQ(XFREAD(buf, 1, sz, file), sz);
    }
    if (file != XBADFILE) {
        XFCLOSE(file);
        file = XBADFILE;
    }

    ExpectNotNull(bio = BIO_new_mem_buf(buf, (int)sz));
    ExpectNotNull((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)));
    XFREE(buf, NULL, DYNAMIC_TYPE_FILE);
    buf = NULL;
    BIO_free(bio);
    bio = NULL;
    ExpectNotNull(pkey3 = EVP_PKEY_new());

    ExpectNotNull(rsa_key = EVP_PKEY_get1_RSA(pkey));
    ExpectIntEQ(EVP_PKEY_set1_RSA(pkey3, rsa_key), WOLFSSL_SUCCESS);

#ifdef WOLFSSL_ERROR_CODE_OPENSSL
    ExpectIntEQ(EVP_PKEY_cmp(pkey, pkey3), 1/* match */);
#else
    ExpectIntEQ(EVP_PKEY_cmp(pkey, pkey3), 0);
#endif

    RSA_free(rsa_key);
    EVP_PKEY_free(pkey3);
    EVP_PKEY_free(pkey);
    pkey  = NULL;
    pkey2 = NULL;

#if defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_CERT_GEN)
    #define BIO_PEM_TEST_CHAR 'a'
    XMEMSET(extra, BIO_PEM_TEST_CHAR, sizeof(extra));

    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(BIO_set_write_buf_size(bio, 4096),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectNotNull(pub_bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(BIO_set_write_buf_size(pub_bio, 4096),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));

    ExpectNull(d2i_PrivateKey(EVP_PKEY_EC, &pkey, &server_key,
        (long)sizeof_server_key_der_2048));
    ExpectNull(pkey);

    ExpectNotNull(wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, &pkey, &server_key,
        (long)sizeof_server_key_der_2048));
    ExpectIntEQ(PEM_write_bio_PrivateKey(NULL, pkey, NULL, NULL, 0, NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_bio_PrivateKey(bio,  NULL, NULL, NULL, 0, NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_bio_PrivateKey(bio,  pkey, NULL, NULL, 0, NULL, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntGT(BIO_pending(bio), 0);
    ExpectIntEQ(BIO_pending(bio), 1679);
    /* Check if the pubkey API writes only the public key */
#ifdef WOLFSSL_KEY_GEN
    ExpectIntEQ(PEM_write_bio_PUBKEY(NULL, pkey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_bio_PUBKEY(pub_bio, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_bio_PUBKEY(pub_bio, pkey), WOLFSSL_SUCCESS);
    ExpectIntGT(BIO_pending(pub_bio), 0);
    /* Previously both the private key and the pubkey calls would write
     * out the private key and the PEM header was the only difference.
     * The public PEM should be significantly shorter than the
     * private key versison. */
    ExpectIntEQ(BIO_pending(pub_bio), 451);
#else
    /* Not supported. */
    ExpectIntEQ(PEM_write_bio_PUBKEY(pub_bio, pkey), 0);
#endif

    /* test creating new EVP_PKEY with good args */
    ExpectNotNull((pkey2 = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)));
    if (pkey && pkey->pkey.ptr && pkey2 && pkey2->pkey.ptr) {
        ExpectIntEQ((int)XMEMCMP(pkey->pkey.ptr, pkey2->pkey.ptr,
            pkey->pkey_sz), 0);
    }

    /* test of reuse of EVP_PKEY */
    ExpectNull(PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL));
    ExpectIntEQ(BIO_pending(bio), 0);
    ExpectIntEQ(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL),
            SSL_SUCCESS);
    /* add 10 extra bytes after PEM */
    ExpectIntEQ(BIO_write(bio, extra, 10), 10);
    ExpectNotNull(PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL));
    ExpectNotNull(pkey);
    if (pkey && pkey->pkey.ptr && pkey2 && pkey2->pkey.ptr) {
        ExpectIntEQ((int)XMEMCMP(pkey->pkey.ptr, pkey2->pkey.ptr,
            pkey->pkey_sz), 0);
    }
    /* check 10 extra bytes still there */
    ExpectIntEQ(BIO_pending(bio), 10);
    ExpectIntEQ(BIO_read(bio, extra, 10), 10);
    for (i = 0; i < 10; i++) {
        ExpectIntEQ(extra[i], BIO_PEM_TEST_CHAR);
    }

    BIO_free(pub_bio);
    BIO_free(bio);
    bio = NULL;
    EVP_PKEY_free(pkey);
    pkey  = NULL;
    EVP_PKEY_free(pkey2);
#endif /* WOLFSSL_KEY_GEN || WOLFSSL_CERT_GEN */
#endif /* OPENSSL_EXTRA && !NO_CERTS && !NO_RSA && USE_CERT_BUFFERS_2048 &&
        * !NO_FILESYSTEM && !NO_BIO */
    return EXPECT_RESULT();
}

/* test loading ECC key using BIO */
int test_wolfSSL_PEM_PrivateKey_ecc(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && defined(HAVE_ECC) && \
    !defined(NO_FILESYSTEM) && !defined(NO_BIO)
    BIO*      bio = NULL;
    EVP_PKEY* pkey  = NULL;
    XFILE file = XBADFILE;
    const char* fname = "./certs/ecc-key.pem";
    const char* fname_ecc_p8  = "./certs/ecc-keyPkcs8.pem";

    size_t sz = 0;
    byte* buf = NULL;
    EVP_PKEY* pkey2 = NULL;
    EVP_PKEY* pkey3 = NULL;
    EC_KEY*   ec_key = NULL;
    int nid = 0;
    BIO* pub_bio = NULL;

    ExpectTrue((file = XFOPEN(fname, "rb")) != XBADFILE);
    ExpectTrue(XFSEEK(file, 0, XSEEK_END) == 0);
    ExpectIntGT(sz = XFTELL(file), 0);
    ExpectTrue(XFSEEK(file, 0, XSEEK_SET) == 0);
    ExpectNotNull(buf = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE));
    if (buf) {
        ExpectIntEQ(XFREAD(buf, 1, sz, file), sz);
    }
    if (file != XBADFILE) {
        XFCLOSE(file);
        file = XBADFILE;
    }

    /* Test using BIO new mem and loading PEM private key */
    ExpectNotNull(bio = BIO_new_mem_buf(buf, (int)sz));
    ExpectNotNull((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)));
    BIO_free(bio);
    bio = NULL;
    XFREE(buf, NULL, DYNAMIC_TYPE_FILE);
    buf = NULL;
    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectNotNull(pub_bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL),
        WOLFSSL_SUCCESS);
    ExpectIntGT(BIO_pending(bio), 0);
    /* No parameters. */
    ExpectIntEQ(BIO_pending(bio), 227);
    /* Check if the pubkey API writes only the public key */
#ifdef WOLFSSL_KEY_GEN
    ExpectIntEQ(PEM_write_bio_PUBKEY(pub_bio, pkey), WOLFSSL_SUCCESS);
    ExpectIntGT(BIO_pending(pub_bio), 0);
    /* Previously both the private key and the pubkey calls would write
     * out the private key and the PEM header was the only difference.
     * The public PEM should be significantly shorter than the
     * private key versison. */
    ExpectIntEQ(BIO_pending(pub_bio), 178);
#endif
    BIO_free(pub_bio);
    BIO_free(bio);
    bio = NULL;
    ExpectNotNull(pkey2 = EVP_PKEY_new());
    ExpectNotNull(pkey3 = EVP_PKEY_new());
    if (pkey2 != NULL) {
         pkey2->type = EVP_PKEY_EC;
    }
    /* Test parameter copy */
    ExpectIntEQ(EVP_PKEY_copy_parameters(pkey2, pkey), 1);


    /* Qt unit test case 1*/
    ExpectNotNull(ec_key = EVP_PKEY_get1_EC_KEY(pkey));
    ExpectIntEQ(EVP_PKEY_set1_EC_KEY(pkey3, ec_key), WOLFSSL_SUCCESS);
    #ifdef WOLFSSL_ERROR_CODE_OPENSSL
    ExpectIntEQ(EVP_PKEY_cmp(pkey, pkey3), 1/* match */);
    #else
    ExpectIntEQ(EVP_PKEY_cmp(pkey, pkey3), 0);
    #endif
    /* Test default digest */
    ExpectIntEQ(EVP_PKEY_get_default_digest_nid(pkey, &nid), 1);
    ExpectIntEQ(nid, NID_sha256);
    EC_KEY_free(ec_key);
    ec_key = NULL;
    EVP_PKEY_free(pkey3);
    pkey3 = NULL;
    EVP_PKEY_free(pkey2);
    pkey2 = NULL;
    EVP_PKEY_free(pkey);
    pkey  = NULL;

    /* Qt unit test case ec pkcs8 key */
    ExpectTrue((file = XFOPEN(fname_ecc_p8, "rb")) != XBADFILE);
    ExpectTrue(XFSEEK(file, 0, XSEEK_END) == 0);
    ExpectIntGT(sz = XFTELL(file), 0);
    ExpectTrue(XFSEEK(file, 0, XSEEK_SET) == 0);
    ExpectNotNull(buf = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE));
    if (buf) {
        ExpectIntEQ(XFREAD(buf, 1, sz, file), sz);
    }
    if (file != XBADFILE) {
        XFCLOSE(file);
        file = XBADFILE;
    }

    ExpectNotNull(bio = BIO_new_mem_buf(buf, (int)sz));
    ExpectNotNull((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)));
    XFREE(buf, NULL, DYNAMIC_TYPE_FILE);
    buf = NULL;
    BIO_free(bio);
    bio = NULL;
    ExpectNotNull(pkey3 = EVP_PKEY_new());
    /* Qt unit test case */
    ExpectNotNull(ec_key = EVP_PKEY_get1_EC_KEY(pkey));
    ExpectIntEQ(EVP_PKEY_set1_EC_KEY(pkey3, ec_key), WOLFSSL_SUCCESS);
#ifdef WOLFSSL_ERROR_CODE_OPENSSL
    ExpectIntEQ(EVP_PKEY_cmp(pkey, pkey3), 1/* match */);
#else
    ExpectIntEQ(EVP_PKEY_cmp(pkey, pkey3), 0);
#endif
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey3);
    EVP_PKEY_free(pkey);
    pkey  = NULL;
#endif
    return EXPECT_RESULT();
}

/* test loading DSA key using BIO */
int test_wolfSSL_PEM_PrivateKey_dsa(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_DSA) && \
    !defined(NO_FILESYSTEM) && !defined(NO_BIO)
#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
    BIO*      bio = NULL;
    EVP_PKEY* pkey  = NULL;

    ExpectNotNull(bio = BIO_new_file("./certs/dsa2048.pem", "rb"));
    /* Private DSA EVP_PKEY */
    ExpectNotNull(pkey = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL, NULL,
        NULL));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
#if defined(OPENSSL_ALL) && !defined(NO_PWDBASED) && defined(HAVE_PKCS8)
#ifdef WOLFSSL_ASN_TEMPLATE
    ExpectIntEQ(PEM_write_bio_PKCS8PrivateKey(bio, pkey, NULL, NULL, 0, NULL,
        NULL), 1216);
#else
    ExpectIntEQ(PEM_write_bio_PKCS8PrivateKey(bio, pkey, NULL, NULL, 0, NULL,
        NULL), 1212);
#endif
#endif

#ifdef WOLFSSL_KEY_GEN
    ExpectIntEQ(PEM_write_bio_PUBKEY(bio, pkey), 1);
#ifdef WOLFSSL_ASN_TEMPLATE
    ExpectIntEQ(BIO_pending(bio), 2394);
#else
    ExpectIntEQ(BIO_pending(bio), 2390);
#endif
    BIO_reset(bio);
#endif

    ExpectIntEQ(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL),
        1);
    ExpectIntEQ(BIO_pending(bio), 1196);

    BIO_free(bio);
    bio = NULL;

    EVP_PKEY_free(pkey);
    pkey  = NULL;
#endif
#endif
    return EXPECT_RESULT();
}

/* test loading DH key using BIO */
int test_wolfSSL_PEM_PrivateKey_dh(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_DH) && \
    !defined(NO_FILESYSTEM) && !defined(NO_BIO)
#if (defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || \
     defined(WOLFSSL_OPENSSH)) && (!defined(HAVE_FIPS) || \
     (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION > 2)))
    BIO*      bio = NULL;
    EVP_PKEY* pkey  = NULL;
    int       expectedBytes = 0;

    ExpectNotNull(bio = BIO_new_file("./certs/dh-priv-2048.pem", "rb"));
    /* Private DH EVP_PKEY */
    ExpectNotNull(pkey = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL, NULL,
        NULL));
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));

#if defined(OPENSSL_ALL) && !defined(NO_PWDBASED) && defined(HAVE_PKCS8)
    expectedBytes += 806;
    ExpectIntEQ(PEM_write_bio_PKCS8PrivateKey(bio, pkey, NULL, NULL, 0, NULL,
        NULL), expectedBytes);
#endif
#ifdef WOLFSSL_KEY_GEN
    ExpectIntEQ(PEM_write_bio_PUBKEY(bio, pkey), 0);
#endif

    ExpectIntEQ(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL),
        1);
    expectedBytes += 806;
    ExpectIntEQ(BIO_pending(bio), expectedBytes);

    BIO_free(bio);
    bio = NULL;

    EVP_PKEY_free(pkey);
    pkey  = NULL;
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_PrivateKey(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_TLS) && \
    (!defined(NO_RSA) || defined(HAVE_ECC)) && defined(USE_CERT_BUFFERS_2048)
#ifndef NO_BIO
    BIO*      bio = NULL;
#endif
    EVP_PKEY* pkey  = NULL;
    const unsigned char* server_key = (const unsigned char*)server_key_der_2048;

#ifndef NO_BIO

    /* test creating new EVP_PKEY with bad arg */
    ExpectNull((pkey = PEM_read_bio_PrivateKey(NULL, NULL, NULL, NULL)));

    /* Test bad EVP_PKEY type. */
    /* New HMAC EVP_PKEY */
    ExpectNotNull(bio = BIO_new_mem_buf("", 1));
    ExpectNotNull(pkey = EVP_PKEY_new());
    if (pkey != NULL) {
        pkey->type = EVP_PKEY_HMAC;
    }
    ExpectIntEQ(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL),
        0);
#if defined(OPENSSL_ALL) && !defined(NO_PWDBASED) && defined(HAVE_PKCS8)
    ExpectIntEQ(PEM_write_bio_PKCS8PrivateKey(bio, pkey, NULL, NULL, 0, NULL,
        NULL), 0);
#endif
#ifdef WOLFSSL_KEY_GEN
    ExpectIntEQ(PEM_write_bio_PUBKEY(bio, pkey),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
#endif
    EVP_PKEY_free(pkey);
    pkey = NULL;
    BIO_free(bio);
    bio = NULL;


    /* key is DES encrypted */
    #if !defined(NO_DES3) && defined(WOLFSSL_ENCRYPTED_KEYS) && \
        !defined(NO_RSA) && !defined(NO_BIO) && !defined(NO_FILESYSTEM) && \
        !defined(NO_MD5) && defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
    {
        XFILE f = XBADFILE;
        wc_pem_password_cb* passwd_cb = NULL;
        void* passwd_cb_userdata;
        SSL_CTX* ctx = NULL;
        char passwd[] = "bad password";

    #ifndef WOLFSSL_NO_TLS12
        #ifndef NO_WOLFSSL_SERVER
        ExpectNotNull(ctx = SSL_CTX_new(TLSv1_2_server_method()));
        #else
        ExpectNotNull(ctx = SSL_CTX_new(TLSv1_2_client_method()));
        #endif
    #else
        #ifndef NO_WOLFSSL_SERVER
        ExpectNotNull(ctx = SSL_CTX_new(TLSv1_3_server_method()));
        #else
        ExpectNotNull(ctx = SSL_CTX_new(TLSv1_3_client_method()));
        #endif
    #endif

        ExpectNotNull(bio = BIO_new_file("./certs/server-keyEnc.pem", "rb"));
        SSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
        ExpectNotNull(passwd_cb = SSL_CTX_get_default_passwd_cb(ctx));
        ExpectNull(passwd_cb_userdata =
            SSL_CTX_get_default_passwd_cb_userdata(ctx));

        /* fail case with password call back */
        ExpectNull(pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL,
                    (void*)passwd));
        BIO_free(bio);
        ExpectNotNull(bio = BIO_new_file("./certs/server-keyEnc.pem", "rb"));
        ExpectNull(pkey = PEM_read_bio_PrivateKey(bio, NULL, passwd_cb,
                    (void*)passwd));
        BIO_free(bio);

        ExpectTrue((f = XFOPEN("./certs/server-keyEnc.pem", "rb")) != XBADFILE);
        ExpectNotNull(bio = BIO_new_fp(f, BIO_CLOSE));
        if ((bio == NULL) && (f != XBADFILE)) {
            XFCLOSE(f);
        }

        /* use callback that works */
        ExpectNotNull(pkey = PEM_read_bio_PrivateKey(bio, NULL, passwd_cb,
                (void*)"yassl123"));

        ExpectIntEQ(SSL_CTX_use_PrivateKey(ctx, pkey), SSL_SUCCESS);

        EVP_PKEY_free(pkey);
        pkey  = NULL;
        BIO_free(bio);
        bio = NULL;
        SSL_CTX_free(ctx);
    }
    #endif /* !defined(NO_DES3) */

#endif /* !NO_BIO */

    #if defined(HAVE_ECC) && !defined(NO_FILESYSTEM)
    {
        unsigned char buf[2048];
        size_t bytes = 0;
        XFILE f = XBADFILE;
        SSL_CTX* ctx = NULL;

    #ifndef WOLFSSL_NO_TLS12
        #ifndef NO_WOLFSSL_SERVER
        ExpectNotNull(ctx = SSL_CTX_new(TLSv1_2_server_method()));
        #else
        ExpectNotNull(ctx = SSL_CTX_new(TLSv1_2_client_method()));
        #endif
    #else
        #ifndef NO_WOLFSSL_SERVER
        ExpectNotNull(ctx = SSL_CTX_new(wolfTLSv1_3_server_method()));
        #else
        ExpectNotNull(ctx = SSL_CTX_new(wolfTLSv1_3_client_method()));
        #endif
    #endif

        ExpectTrue((f = XFOPEN("./certs/ecc-key.der", "rb")) != XBADFILE);
        ExpectIntGT(bytes = (size_t)XFREAD(buf, 1, sizeof(buf), f), 0);
        if (f != XBADFILE)
            XFCLOSE(f);

        server_key = buf;
        pkey = NULL;
        ExpectNull(d2i_PrivateKey(EVP_PKEY_RSA, &pkey, &server_key,
            (long int)bytes));
        ExpectNull(pkey);
        ExpectNotNull(d2i_PrivateKey(EVP_PKEY_EC, &pkey, &server_key,
            (long int)bytes));
        ExpectIntEQ(SSL_CTX_use_PrivateKey(ctx, pkey), SSL_SUCCESS);

        EVP_PKEY_free(pkey);
        pkey = NULL;
        SSL_CTX_free(ctx);
        server_key = NULL;
    }
    #endif

#ifndef NO_BIO
    (void)bio;
#endif
    (void)pkey;
    (void)server_key;
#endif /* OPENSSL_EXTRA && !NO_CERTS && !NO_RSA && USE_CERT_BUFFERS_2048 */
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_file_RSAKey(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && \
    defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && !defined(NO_CERTS)
    RSA* rsa = NULL;
    XFILE fp = XBADFILE;

    ExpectTrue((fp = XFOPEN("./certs/rsa-pub-2048.pem", "rb")) != XBADFILE);
    ExpectNotNull((rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL)));
    if (fp != XBADFILE)
        XFCLOSE(fp);
    ExpectIntEQ(RSA_size(rsa), 256);

    ExpectIntEQ(PEM_write_RSAPublicKey(XBADFILE, rsa),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_RSAPublicKey(stderr, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_RSAPublicKey(stderr, rsa), WOLFSSL_SUCCESS);

    ExpectIntEQ(PEM_write_RSA_PUBKEY(XBADFILE, rsa),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_RSA_PUBKEY(stderr, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_RSA_PUBKEY(stderr, rsa), WOLFSSL_SUCCESS);

    RSA_free(rsa);
#endif /* defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && \
         (defined(WOLFSSL_KEY_GEN) || WOLFSSL_CERT_GEN) && \
         !defined(NO_FILESYSTEM) && !defined(NO_RSA) && !defined(NO_CERTS) */
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_file_RSAPrivateKey(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && defined(OPENSSL_EXTRA) && defined(WOLFSSL_KEY_GEN) && \
    !defined(NO_FILESYSTEM) && \
    (defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM))
    RSA* rsa = NULL;
    XFILE f = NULL;

    ExpectTrue((f = XFOPEN(svrKeyFile, "rb")) != XBADFILE);
    ExpectNotNull((rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL)));
    ExpectIntEQ(RSA_size(rsa), 256);
    if (f != XBADFILE) {
        XFCLOSE(f);
        f = XBADFILE;
    }

    ExpectIntEQ(PEM_write_RSAPrivateKey(XBADFILE, rsa, NULL, NULL, 0, NULL,
        NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_RSAPrivateKey(stderr, NULL, NULL, NULL, 0, NULL,
        NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_RSAPrivateKey(stderr, rsa, NULL, NULL, 0, NULL, NULL),
        WOLFSSL_SUCCESS);

    RSA_free(rsa);

#ifdef HAVE_ECC
    ExpectTrue((f = XFOPEN(eccKeyFile, "rb")) != XBADFILE);
    ExpectNull((rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL)));
    if (f != XBADFILE)
        XFCLOSE(f);
#endif /* HAVE_ECC */
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) */
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_read_RSA_PUBKEY(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    XFILE file = XBADFILE;
    const char* fname = "./certs/client-keyPub.pem";
    RSA *rsa = NULL;

    ExpectNull(wolfSSL_PEM_read_RSA_PUBKEY(XBADFILE, NULL, NULL, NULL));

    ExpectTrue((file = XFOPEN(fname, "rb")) != XBADFILE);
    ExpectNotNull((rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)));
    ExpectIntEQ(RSA_size(rsa), 256);
    RSA_free(rsa);
    if (file != XBADFILE)
       XFCLOSE(file);
#endif /* defined(OPENSSL_EXTRA) && !defined(NO_CERTS) */
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_read_bio(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
   !defined(NO_FILESYSTEM) && !defined(NO_RSA) && !defined(NO_BIO)
    byte buff[6000];
    XFILE f = XBADFILE;
    int  bytes = 0;
    X509* x509 = NULL;
    BIO*  bio = NULL;
    BUF_MEM* buf = NULL;

    ExpectTrue((f = XFOPEN(cliCertFile, "rb")) != XBADFILE);
    ExpectIntGT(bytes = (int)XFREAD(buff, 1, sizeof(buff), f), 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    ExpectNull(x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL));
    ExpectNotNull(bio = BIO_new_mem_buf((void*)buff, bytes));
    ExpectIntEQ(BIO_set_mem_eof_return(bio, -0xDEAD), 1);
    ExpectNotNull(x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL));
    ExpectIntEQ((int)BIO_set_fd(bio, 0, BIO_CLOSE), 1);
    /* BIO should return the set EOF value */
    ExpectIntEQ(BIO_read(bio, buff, sizeof(buff)), -0xDEAD);
    ExpectIntEQ(BIO_set_close(bio, BIO_NOCLOSE), 1);
    ExpectIntEQ(BIO_set_close(NULL, BIO_NOCLOSE), 1);
    ExpectIntEQ(SSL_SUCCESS, BIO_get_mem_ptr(bio, &buf));

    BIO_free(bio);
    BUF_MEM_free(buf);
    X509_free(x509);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_bio_RSAKey(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && \
    defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && !defined(NO_CERTS)  && !defined(NO_BIO)
    RSA* rsa = NULL;
    BIO* bio = NULL;

    /* PrivateKey */
    ExpectNotNull(bio = BIO_new_file(svrKeyFile, "rb"));
    ExpectNull((rsa = PEM_read_bio_RSAPrivateKey(NULL, NULL, NULL, NULL)));
    ExpectNotNull(PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL));
    ExpectNotNull(rsa);
    ExpectIntEQ(RSA_size(rsa), 256);
    ExpectIntEQ(PEM_write_bio_RSAPrivateKey(NULL, NULL, NULL, NULL, 0, NULL,
        NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    BIO_free(bio);
    bio = NULL;
    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL,
        NULL), WOLFSSL_SUCCESS);
    BIO_free(bio);
    bio = NULL;
    RSA_free(rsa);
    rsa = NULL;

    /* PUBKEY */
    ExpectNotNull(bio = BIO_new_file("./certs/rsa-pub-2048.pem", "rb"));
    ExpectNull((rsa = PEM_read_bio_RSA_PUBKEY(NULL, NULL, NULL, NULL)));
    ExpectNotNull((rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL)));
    ExpectIntEQ(RSA_size(rsa), 256);
    ExpectIntEQ(PEM_write_bio_RSA_PUBKEY(NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    BIO_free(bio);
    bio = NULL;
    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_RSA_PUBKEY(bio, rsa), WOLFSSL_SUCCESS);
    BIO_free(bio);
    bio = NULL;

    RSA_free(rsa);
    rsa = NULL;

    /* Ensure that keys beginning with BEGIN RSA PUBLIC KEY can be read, too. */
    ExpectNotNull(bio = BIO_new_file("./certs/server-keyPub.pem", "rb"));
    ExpectNotNull((rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL)));
    BIO_free(bio);
    bio = NULL;
    RSA_free(rsa);
    rsa = NULL;

    #ifdef HAVE_ECC
    /* ensure that non-rsa keys do not work */
    ExpectNotNull(bio = BIO_new_file(eccKeyFile, "rb")); /* ecc key */
    ExpectNull((rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL)));
    ExpectNull((rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL)));
    BIO_free(bio);
    bio = NULL;
    RSA_free(rsa);
    rsa = NULL;
    #endif /* HAVE_ECC */
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_bio_RSAPrivateKey(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && \
   !defined(NO_FILESYSTEM) && !defined(NO_RSA) && !defined(NO_BIO)
    RSA* rsa = NULL;
    RSA* rsa_dup = NULL;
    BIO* bio = NULL;

    ExpectNotNull(bio = BIO_new_file(svrKeyFile, "rb"));
    ExpectNotNull((rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL)));
    ExpectIntEQ(RSA_size(rsa), 256);

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
    ExpectNull(rsa_dup = RSAPublicKey_dup(NULL));
    /* Test duplicating empty key. */
    ExpectNotNull(rsa_dup = RSA_new());
    ExpectNull(RSAPublicKey_dup(rsa_dup));
    RSA_free(rsa_dup);
    rsa_dup = NULL;
    ExpectNotNull(rsa_dup = RSAPublicKey_dup(rsa));
    ExpectPtrNE(rsa_dup, rsa);
#endif

    /* test if valgrind complains about unreleased memory */
    RSA_up_ref(rsa);
    RSA_free(rsa);

    BIO_free(bio);
    bio = NULL;
    RSA_free(rsa);
    rsa = NULL;
    RSA_free(rsa_dup);
    rsa_dup = NULL;

#ifdef HAVE_ECC
    ExpectNotNull(bio = BIO_new_file(eccKeyFile, "rb"));
    ExpectNull((rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL)));

    BIO_free(bio);
#endif /* HAVE_ECC */
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_bio_DSAKey(void)
{
    EXPECT_DECLS;
#ifndef HAVE_SELFTEST
#if (defined(WOLFSSL_QT) || defined(OPENSSL_ALL)) && !defined(NO_CERTS) && \
    defined(WOLFSSL_KEY_GEN) && !defined(NO_FILESYSTEM) && \
    !defined(NO_DSA) && !defined(NO_BIO)
    DSA* dsa = NULL;
    BIO* bio = NULL;

    /* PrivateKey */
    ExpectNotNull(bio = BIO_new_file("./certs/1024/dsa1024.pem", "rb"));
    ExpectNull((dsa = PEM_read_bio_DSAPrivateKey(NULL, NULL, NULL, NULL)));
    ExpectNotNull((dsa = PEM_read_bio_DSAPrivateKey(bio, NULL, NULL, NULL)));
    ExpectIntEQ(BN_num_bytes(dsa->g), 128);
    ExpectIntEQ(PEM_write_bio_DSAPrivateKey(NULL, NULL, NULL, NULL, 0, NULL,
        NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    BIO_free(bio);
    bio = NULL;
    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_DSAPrivateKey(bio, dsa, NULL, NULL, 0, NULL,
        NULL), WOLFSSL_SUCCESS);
    BIO_free(bio);
    bio = NULL;
    DSA_free(dsa);
    dsa = NULL;

    /* PUBKEY */
    ExpectNotNull(bio = BIO_new_file("./certs/1024/dsa-pub-1024.pem", "rb"));
    ExpectNull((dsa = PEM_read_bio_DSA_PUBKEY(NULL, NULL, NULL, NULL)));
    ExpectNotNull((dsa = PEM_read_bio_DSA_PUBKEY(bio, NULL, NULL, NULL)));
    ExpectIntEQ(BN_num_bytes(dsa->g), 128);
    ExpectIntEQ(PEM_write_bio_DSA_PUBKEY(NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    BIO_free(bio);
    bio = NULL;
    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_DSA_PUBKEY(bio, dsa), WOLFSSL_SUCCESS);
    BIO_free(bio);
    bio = NULL;
    DSA_free(dsa);
    dsa = NULL;

    #ifdef HAVE_ECC
    /* ensure that non-dsa keys do not work */
    ExpectNotNull(bio = BIO_new_file(eccKeyFile, "rb")); /* ecc key */
    ExpectNull((dsa = PEM_read_bio_DSAPrivateKey(bio, NULL, NULL, NULL)));
    ExpectNull((dsa = PEM_read_bio_DSA_PUBKEY(bio, NULL, NULL, NULL)));
    BIO_free(bio);
    bio = NULL;
    DSA_free(dsa);
    dsa = NULL;
    #endif /* HAVE_ECC */
#endif
#endif /* HAVE_SELFTEST */
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_bio_ECKey(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && \
    defined(WOLFSSL_KEY_GEN) && !defined(NO_FILESYSTEM) && \
    defined(HAVE_ECC) && !defined(NO_BIO)
    EC_KEY* ec = NULL;
    EC_KEY* ec2;
    BIO* bio = NULL;
#if defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)
    unsigned char* pem = NULL;
    int pLen;
#endif
    static char ec_key_bad_1[] = "-----BEGIN PUBLIC KEY-----\n"
                                 "MAA=\n"
                                 "-----END PUBLIC KEY-----";
    static char ec_priv_key_bad_1[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                      "MAA=\n"
                                      "-----END EC PRIVATE KEY-----";

    /* PrivateKey */
    ExpectNotNull(bio = BIO_new_file("./certs/ecc-key.pem", "rb"));
    ExpectNull((ec = PEM_read_bio_ECPrivateKey(NULL, NULL, NULL, NULL)));
    ec2 = NULL;
    ExpectNotNull((ec = PEM_read_bio_ECPrivateKey(bio, &ec2, NULL, NULL)));
    ExpectIntEQ(ec == ec2, 1);
    ExpectIntEQ(wc_ecc_size((ecc_key*)ec->internal), 32);
    ExpectIntEQ(PEM_write_bio_ECPrivateKey(NULL, NULL, NULL, NULL, 0, NULL,
        NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_bio_ECPrivateKey(bio, NULL, NULL, NULL, 0, NULL,
        NULL), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_bio_ECPrivateKey(NULL, ec, NULL, NULL, 0, NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    BIO_free(bio);
    bio = NULL;
    /* Public key data - fail. */
    ExpectNotNull(bio = BIO_new_file("./certs/ecc-client-keyPub.pem", "rb"));
    ExpectNull(PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;
    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, NULL, \
                                           NULL), WOLFSSL_SUCCESS);
    BIO_free(bio);
    bio = NULL;

    ExpectIntEQ(PEM_write_ECPrivateKey(XBADFILE, NULL, NULL, NULL, 0, NULL,
        NULL),WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_ECPrivateKey(stderr, NULL, NULL, NULL, 0, NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_ECPrivateKey(XBADFILE, ec, NULL, NULL, 0, NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_ECPrivateKey(stderr, ec, NULL, NULL, 0, NULL, NULL),
        WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_PEM_write_mem_ECPrivateKey(NULL, NULL, NULL, 0, NULL,
        NULL), 0);
#if defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)
    ExpectIntEQ(wolfSSL_PEM_write_mem_ECPrivateKey(ec, NULL, NULL, 0, NULL,
        NULL), 0);
    ExpectIntEQ(wolfSSL_PEM_write_mem_ECPrivateKey(NULL, NULL, NULL, 0, &pem,
        NULL), 0);
    ExpectIntEQ(wolfSSL_PEM_write_mem_ECPrivateKey(NULL, NULL, NULL, 0, NULL,
        &pLen), 0);
    ExpectIntEQ(wolfSSL_PEM_write_mem_ECPrivateKey(NULL, NULL, NULL, 0, &pem,
        &pLen), 0);
    ExpectIntEQ(wolfSSL_PEM_write_mem_ECPrivateKey(ec, NULL, NULL, 0, NULL,
        &pLen), 0);
    ExpectIntEQ(wolfSSL_PEM_write_mem_ECPrivateKey(ec, NULL, NULL, 0, &pem,
        NULL), 0);
    ExpectIntEQ(wolfSSL_PEM_write_mem_ECPrivateKey(ec, NULL, NULL, 0, &pem,
        &pLen), 1);
    ExpectIntGT(pLen, 0);
    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    EC_KEY_free(ec);
    ec = NULL;

    /* PUBKEY */
    ExpectNotNull(bio = BIO_new_file("./certs/ecc-client-keyPub.pem", "rb"));
    ExpectNull((ec = PEM_read_bio_EC_PUBKEY(NULL, NULL, NULL, NULL)));
    ec2 = NULL;
    ExpectNotNull((ec = PEM_read_bio_EC_PUBKEY(bio, &ec2, NULL, NULL)));
    ExpectIntEQ(ec == ec2, 1);
    ExpectIntEQ(wc_ecc_size((ecc_key*)ec->internal), 32);
    ExpectIntEQ(PEM_write_bio_EC_PUBKEY(NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    BIO_free(bio);
    bio = NULL;
    /* Test 0x30, 0x00 fails. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_key_bad_1,
        sizeof(ec_key_bad_1)));
    ExpectNull(PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;

    /* Private key data - fail. */
    ExpectNotNull(bio = BIO_new_file("./certs/ecc-key.pem", "rb"));
    ExpectNull(PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;
    ExpectNotNull(bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_EC_PUBKEY(bio, ec), WOLFSSL_SUCCESS);
    BIO_free(bio);
    bio = NULL;

    /* Same test as above, but with a file pointer rather than a BIO. */
    ExpectIntEQ(PEM_write_EC_PUBKEY(NULL, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_EC_PUBKEY(NULL, ec),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_EC_PUBKEY(stderr, NULL),
        WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(PEM_write_EC_PUBKEY(stderr, ec), WOLFSSL_SUCCESS);

    EC_KEY_free(ec);
    ec = NULL;

    #ifndef NO_RSA
    /* ensure that non-ec keys do not work */
    ExpectNotNull(bio = BIO_new_file(svrKeyFile, "rb")); /* rsa key */
    ExpectNull((ec = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL)));
    ExpectNull((ec = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL)));
    BIO_free(bio);
    bio = NULL;
    EC_KEY_free(ec);
    ec = NULL;
    #endif /* !NO_RSA */
    /* Test 0x30, 0x00 fails. */
    ExpectNotNull(bio = BIO_new_mem_buf((unsigned char*)ec_priv_key_bad_1,
        sizeof(ec_priv_key_bad_1)));
    ExpectNull(PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL));
    BIO_free(bio);
    bio = NULL;
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_PUBKEY(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && !defined(NO_BIO)
    BIO*      bio = NULL;
    EVP_PKEY* pkey  = NULL;

    /* test creating new EVP_PKEY with bad arg */
    ExpectNull((pkey = PEM_read_bio_PUBKEY(NULL, NULL, NULL, NULL)));

    /* test loading ECC key using BIO */
#if defined(HAVE_ECC) && !defined(NO_FILESYSTEM)
    {
        XFILE file = XBADFILE;
        const char* fname = "./certs/ecc-client-keyPub.pem";
        size_t sz = 0;
        byte* buf = NULL;

        EVP_PKEY* pkey2 = NULL;
        EC_KEY*   ec_key = NULL;

        ExpectTrue((file = XFOPEN(fname, "rb")) != XBADFILE);
        ExpectIntEQ(XFSEEK(file, 0, XSEEK_END), 0);
        ExpectIntGT(sz = XFTELL(file), 0);
        ExpectIntEQ(XFSEEK(file, 0, XSEEK_SET), 0);
        ExpectNotNull(buf = (byte*)XMALLOC(sz, NULL, DYNAMIC_TYPE_FILE));
        if (buf != NULL) {
            ExpectIntEQ(XFREAD(buf, 1, sz, file), sz);
        }
        if (file != XBADFILE) {
            XFCLOSE(file);
        }

        /* Test using BIO new mem and loading PEM private key */
        ExpectNotNull(bio = BIO_new_mem_buf(buf, (int)sz));
        ExpectNotNull((pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)));
        BIO_free(bio);
        bio = NULL;
        EVP_PKEY_free(pkey);
        pkey = NULL;
        ExpectNotNull(bio = BIO_new_mem_buf(buf, (int)sz));
        ExpectNotNull(pkey = EVP_PKEY_new());
        ExpectPtrEq(PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL), pkey);
        XFREE(buf, NULL, DYNAMIC_TYPE_FILE);
        BIO_free(bio);
        bio = NULL;

        /* Qt unit test case*/
        ExpectNotNull(pkey2 = EVP_PKEY_new());
        ExpectNotNull(ec_key = EVP_PKEY_get1_EC_KEY(pkey));
        ExpectIntEQ(EVP_PKEY_set1_EC_KEY(pkey2, ec_key), WOLFSSL_SUCCESS);
    #ifdef WOLFSSL_ERROR_CODE_OPENSSL
        ExpectIntEQ(EVP_PKEY_cmp(pkey, pkey2), 1/* match */);
    #else
        ExpectIntEQ(EVP_PKEY_cmp(pkey, pkey2), 0);
    #endif

        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey2);
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
#endif

    (void)bio;
    (void)pkey;
#endif
    return EXPECT_RESULT();
}

