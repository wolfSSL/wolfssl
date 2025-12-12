/* test_ossl_x509_name.c
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
#include <tests/api/api.h>
#include <tests/api/test_ossl_x509_name.h>

int test_wolfSSL_X509_NAME_get_entry(void)
{
    EXPECT_DECLS;
#if !defined(NO_CERTS) && !defined(NO_RSA) && !defined(NO_FILESYSTEM)
#if defined(OPENSSL_ALL) || \
        (defined(OPENSSL_EXTRA) && \
            (defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)))
    /* use openssl like name to test mapping */
    X509_NAME_ENTRY* ne = NULL;
    X509_NAME* name = NULL;
    X509* x509 = NULL;
    ASN1_STRING* asn = NULL;
    char* subCN = NULL;
    int idx = 0;
    ASN1_OBJECT *object = NULL;
#if defined(WOLFSSL_APACHE_HTTPD) || defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX)
#ifndef NO_BIO
    BIO* bio = NULL;
#endif
#endif

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(cliCertFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = X509_get_subject_name(x509));
    ExpectIntGE(idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1), 0);
    ExpectNotNull(ne = X509_NAME_get_entry(name, idx));
    ExpectNull(X509_NAME_ENTRY_get_data(NULL));
    ExpectNotNull(asn = X509_NAME_ENTRY_get_data(ne));
    ExpectNotNull(subCN = (char*)ASN1_STRING_data(asn));
    wolfSSL_FreeX509(x509);
    x509 = NULL;

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(cliCertFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = X509_get_subject_name(x509));
    ExpectIntGE(idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1), 0);

#if defined(WOLFSSL_APACHE_HTTPD) || defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX)
#ifndef NO_BIO
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(X509_NAME_print_ex(bio, name, 4,
                    (XN_FLAG_RFC2253 & ~XN_FLAG_DN_REV)), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_NAME_print_ex_fp(XBADFILE, name, 4,
                    (XN_FLAG_RFC2253 & ~XN_FLAG_DN_REV)), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_NAME_print_ex_fp(stderr, name, 4,
                    (XN_FLAG_RFC2253 & ~XN_FLAG_DN_REV)), WOLFSSL_SUCCESS);
    BIO_free(bio);
#endif
#endif

    ExpectNotNull(ne = X509_NAME_get_entry(name, idx));
    ExpectNotNull(object = X509_NAME_ENTRY_get_object(ne));
    wolfSSL_FreeX509(x509);
#endif /* OPENSSL_ALL || (OPENSSL_EXTRA && (KEEP_PEER_CERT || SESSION_CERTS) */
#endif /* !NO_CERTS && !NO_RSA && !NO_FILESYSTEM */

    return EXPECT_RESULT();
}

int test_wolfSSL_X509_NAME(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && defined(WOLFSSL_CERT_GEN) && \
    (defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_EXT) || \
     defined(OPENSSL_EXTRA))
    X509* x509 = NULL;
#ifndef OPENSSL_EXTRA
    const unsigned char* c = NULL;
    int bytes = 0;
#endif
    unsigned char buf[4096];
    XFILE f = XBADFILE;
    const X509_NAME* a = NULL;
    const X509_NAME* b = NULL;
    X509_NAME* d2i_name = NULL;
    int sz = 0;
    unsigned char* tmp = NULL;
    char file[] = "./certs/ca-cert.der";
#ifndef OPENSSL_EXTRA_X509_SMALL
    byte empty[] = { /* CN=empty emailAddress= */
        0x30, 0x21, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0C, 0x05, 0x65, 0x6D, 0x70,
        0x74, 0x79, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09,
        0x01, 0x16, 0x00
    };
#endif
#if defined(OPENSSL_EXTRA) && !defined(NO_PWDBASED)
    byte   digest[64]; /* max digest size */
    word32 digestSz;
#endif

#ifndef OPENSSL_EXTRA_X509_SMALL
    /* test compile of deprecated function, returns 0 */
    ExpectIntEQ(CRYPTO_thread_id(), 0);
#endif

    ExpectNotNull(a = X509_NAME_new());
    ExpectNotNull(b = X509_NAME_new());
#ifndef OPENSSL_EXTRA_X509_SMALL
    ExpectIntEQ(X509_NAME_cmp(a, b), 0);
#endif
    X509_NAME_free((X509_NAME*)b);
    X509_NAME_free((X509_NAME*)a);
    a = NULL;

    ExpectTrue((f = XFOPEN(file, "rb")) != XBADFILE);
#ifndef OPENSSL_EXTRA
    ExpectIntGT(bytes = (int)XFREAD(buf, 1, sizeof(buf), f), 0);
    if (f != XBADFILE)
        XFCLOSE(f);

    c = buf;
    ExpectNotNull(x509 = wolfSSL_X509_d2i_ex(NULL, c, bytes, HEAP_HINT));
#else
    ExpectNull(wolfSSL_X509_d2i_fp(NULL, XBADFILE));
    ExpectNotNull(wolfSSL_X509_d2i_fp(&x509, f));
    if (f != XBADFILE)
        XFCLOSE(f);
#endif

    /* test cmp function */
    ExpectNull(X509_get_issuer_name(NULL));
    ExpectNotNull(a = X509_get_issuer_name(x509));
    ExpectNull(X509_get_subject_name(NULL));
    ExpectNotNull(b = X509_get_subject_name(x509));
#ifdef KEEP_PEER_CERT
    ExpectNull(wolfSSL_X509_get_subjectCN(NULL));
    ExpectNotNull(wolfSSL_X509_get_subjectCN(x509));
#endif

#if defined(OPENSSL_EXTRA)
    ExpectIntEQ(X509_check_issued(NULL, NULL),
        WOLFSSL_X509_V_ERR_SUBJECT_ISSUER_MISMATCH);
    ExpectIntEQ(X509_check_issued(x509, NULL),
        WOLFSSL_X509_V_ERR_SUBJECT_ISSUER_MISMATCH);
    ExpectIntEQ(X509_check_issued(NULL, x509),
        WOLFSSL_X509_V_ERR_SUBJECT_ISSUER_MISMATCH);
    ExpectIntEQ(X509_check_issued(x509, x509), WOLFSSL_X509_V_OK);
    ExpectIntEQ(X509_NAME_cmp(NULL, NULL), -2);
    ExpectIntEQ(X509_NAME_cmp(NULL, b), -2);
    ExpectIntEQ(X509_NAME_cmp(a, NULL), -2);
    ExpectIntEQ(X509_NAME_cmp(a, b), 0); /* self signed should be 0 */

#if !defined(NO_PWDBASED)
    ExpectIntEQ(wolfSSL_X509_NAME_digest(NULL, NULL, NULL, NULL), 0);
    ExpectIntEQ(wolfSSL_X509_NAME_digest(a, NULL, NULL, NULL), 0);
#ifndef NO_SHA256
    ExpectIntEQ(wolfSSL_X509_NAME_digest(NULL, wolfSSL_EVP_sha256(), NULL,
        NULL), 0);
#endif
    ExpectIntEQ(wolfSSL_X509_NAME_digest(NULL, NULL, digest, NULL), 0);
    ExpectIntEQ(wolfSSL_X509_NAME_digest(NULL, NULL, NULL, &digestSz), 0);
    ExpectIntEQ(wolfSSL_X509_NAME_digest(a, NULL, digest,
        &digestSz), 0);
#ifndef NO_SHA256
    ExpectIntEQ(wolfSSL_X509_NAME_digest(NULL, wolfSSL_EVP_sha256(), digest,
        &digestSz), 0);
    ExpectIntEQ(wolfSSL_X509_NAME_digest(a, wolfSSL_EVP_sha256(), NULL,
        &digestSz), 0);
    ExpectIntEQ(wolfSSL_X509_NAME_digest(a, wolfSSL_EVP_sha256(), digest,
        NULL), 1);
    ExpectIntEQ(wolfSSL_X509_NAME_digest(a, wolfSSL_EVP_sha256(), digest,
        &digestSz), 1);
    ExpectTrue(digestSz == 32);
#endif
#else
    ExpectIntEQ(wolfSSL_X509_NAME_digest(NULL, NULL, NULL, NULL),
        NOT_COMPILED_IN);
#endif
#endif /* OPENSSL_EXTRA */

    tmp = buf;
    ExpectIntGT((sz = i2d_X509_NAME((X509_NAME*)a, &tmp)), 0);
    if (sz > 0 && tmp == buf) {
        fprintf(stderr, "\nERROR - %s line %d failed with:", __FILE__,
            __LINE__);
        fprintf(stderr, " Expected pointer to be incremented\n");
        abort();
    }

#ifndef OPENSSL_EXTRA_X509_SMALL
    tmp = buf;
    ExpectNotNull(d2i_name = d2i_X509_NAME(NULL, &tmp, sz));
#endif

    /* if output parameter is NULL, should still return required size. */
    ExpectIntGT((sz = i2d_X509_NAME((X509_NAME*)b, NULL)), 0);
    /* retry but with the function creating a buffer */
    tmp = NULL;
    ExpectIntGT((sz = i2d_X509_NAME((X509_NAME*)b, &tmp)), 0);
    XFREE(tmp, NULL, DYNAMIC_TYPE_OPENSSL);
    tmp = NULL;

#ifdef WOLFSSL_CERT_NAME_ALL
    /* test for givenName and name */
    {
        WOLFSSL_X509_NAME_ENTRY* entry = NULL;
        WOLFSSL_X509_NAME_ENTRY empty;
        const byte gName[] = "test-given-name";
        const byte name[] = "test-name";

        XMEMSET(&empty, 0, sizeof(empty));

        ExpectNull(wolfSSL_X509_NAME_ENTRY_create_by_NID(NULL,
            NID_givenName, ASN_UTF8STRING, NULL, sizeof(gName)));
        ExpectNotNull(entry = wolfSSL_X509_NAME_ENTRY_create_by_NID(NULL,
            NID_givenName, ASN_UTF8STRING, gName, sizeof(gName)));
        ExpectNotNull(wolfSSL_X509_NAME_ENTRY_create_by_NID(&entry,
            NID_givenName, ASN_UTF8STRING, gName, sizeof(gName)));
        ExpectIntEQ(wolfSSL_X509_NAME_add_entry(NULL         , NULL  , -1, 0),
            0);
        ExpectIntEQ(wolfSSL_X509_NAME_add_entry((X509_NAME*)b, NULL  , -1, 0),
            0);
        ExpectIntEQ(wolfSSL_X509_NAME_add_entry(NULL         , entry , -1, 0),
            0);
        ExpectIntEQ(wolfSSL_X509_NAME_add_entry((X509_NAME*)b, &empty, -1, 0),
            0);
        ExpectIntEQ(wolfSSL_X509_NAME_add_entry((X509_NAME*)b, entry , 99, 0),
            0);
        ExpectIntEQ(wolfSSL_X509_NAME_add_entry((X509_NAME*)b, entry , -1, 0),
            1);
        wolfSSL_X509_NAME_ENTRY_free(entry);
        entry = NULL;

        ExpectNotNull(wolfSSL_X509_NAME_ENTRY_create_by_NID(&entry,
            NID_name, ASN_UTF8STRING, name, sizeof(name)));
        ExpectIntEQ(wolfSSL_X509_NAME_add_entry((X509_NAME*)b, entry, -1, 0),
            1);
        wolfSSL_X509_NAME_ENTRY_free(entry);

        tmp = NULL;
        ExpectIntGT((sz = i2d_X509_NAME((X509_NAME*)b, &tmp)), 0);
        XFREE(tmp, NULL, DYNAMIC_TYPE_OPENSSL);
    }
#endif

    b = NULL;
    ExpectNull(X509_NAME_dup(NULL));
    ExpectNotNull(b = X509_NAME_dup((X509_NAME*)a));
#ifndef OPENSSL_EXTRA_X509_SMALL
    ExpectIntEQ(X509_NAME_cmp(a, b), 0);
#endif
    ExpectIntEQ(X509_NAME_entry_count(NULL), 0);
    ExpectIntEQ(X509_NAME_entry_count((X509_NAME*)b), 7);
    X509_NAME_free((X509_NAME*)b);
    ExpectNotNull(b = wolfSSL_X509_NAME_new());
    ExpectIntEQ(X509_NAME_entry_count((X509_NAME*)b), 0);
    ExpectIntEQ(wolfSSL_X509_NAME_copy(NULL, NULL), BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_X509_NAME_copy((X509_NAME*)a, NULL), BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_X509_NAME_copy(NULL, (X509_NAME*)b), BAD_FUNC_ARG);
    ExpectIntEQ(wolfSSL_X509_NAME_copy((X509_NAME*)a, (X509_NAME*)b), 1);
    ExpectIntEQ(X509_NAME_entry_count((X509_NAME*)b), 7);
    X509_NAME_free((X509_NAME*)b);
    X509_NAME_free(d2i_name);
    d2i_name = NULL;
    X509_free(x509);

#ifndef OPENSSL_EXTRA_X509_SMALL
    /* test with an empty domain component */
    tmp = empty;
    sz  = sizeof(empty);
    ExpectNotNull(d2i_name = d2i_X509_NAME(NULL, &tmp, sz));
    ExpectIntEQ(X509_NAME_entry_count(d2i_name), 2);

    /* size of empty emailAddress will be 0 */
    tmp = buf;
    ExpectIntEQ(X509_NAME_get_text_by_NID(d2i_name, NID_emailAddress,
                (char*)tmp, sizeof(buf)), 0);

    /* should contain no organization name */
    tmp = buf;
    ExpectIntEQ(X509_NAME_get_text_by_NID(d2i_name, NID_organizationName,
                (char*)tmp, sizeof(buf)), -1);
    X509_NAME_free(d2i_name);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_NAME_hash(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && !defined(NO_SHA) && !defined(NO_BIO)
    BIO* bio = NULL;
    X509* x509 = NULL;
    X509_NAME* name = NULL;

    ExpectIntEQ(X509_NAME_hash(NULL), 0);
    ExpectNotNull(name = wolfSSL_X509_NAME_new_ex(NULL));
    ExpectIntEQ(X509_NAME_hash(name), 0);
    X509_NAME_free(name);

    ExpectNotNull(bio = BIO_new(BIO_s_file()));
    ExpectIntGT(BIO_read_filename(bio, svrCertFile), 0);
    ExpectNotNull(PEM_read_bio_X509(bio, &x509, NULL, NULL));
    ExpectIntEQ(X509_NAME_hash(X509_get_subject_name(x509)), 0x137DC03F);
    ExpectIntEQ(X509_NAME_hash(X509_get_issuer_name(x509)), 0xFDB2DA4);
    X509_free(x509);
    BIO_free(bio);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_NAME_print_ex(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
     (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
     defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
     defined(WOLFSSL_OPENSSH) || defined(HAVE_SBLIM_SFCB)))) && \
    !defined(NO_BIO) && !defined(NO_RSA)
    int memSz = 0;
    byte* mem = NULL;
    BIO* bio = NULL;
    BIO* membio = NULL;
    X509* x509 = NULL;
    X509_NAME* name = NULL;
    X509_NAME* empty = NULL;

    const char* expNormal  = "C=US, CN=wolfssl.com";
    const char* expEqSpace = "C = US, CN = wolfssl.com";
    const char* expReverse = "CN=wolfssl.com, C=US";

    const char* expNotEscaped = "C= US,+\"\\ , CN=#wolfssl.com<>;";
    const char* expNotEscapedRev = "CN=#wolfssl.com<>;, C= US,+\"\\ ";
    const char* expRFC5523 =
        "CN=\\#wolfssl.com\\<\\>\\;, C=\\ US\\,\\+\\\"\\\\\\ ";

    /* Test with real cert (svrCertFile) first */
    ExpectNotNull(bio = BIO_new(BIO_s_file()));
    ExpectIntGT(BIO_read_filename(bio, svrCertFile), 0);
    ExpectNotNull(PEM_read_bio_X509(bio, &x509, NULL, NULL));
    ExpectNotNull(name = X509_get_subject_name(x509));

    /* Test without flags */
    ExpectNotNull(membio = BIO_new(BIO_s_mem()));
    ExpectNotNull(empty = wolfSSL_X509_NAME_new());
    ExpectIntEQ(X509_NAME_print_ex(NULL, NULL, 0, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_NAME_print_ex(membio, NULL, 0, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_NAME_print_ex(NULL, name, 0, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_NAME_print_ex(membio, empty, 0, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_NAME_print_ex(membio, name, 0, 0), WOLFSSL_SUCCESS);
    wolfSSL_X509_NAME_free(empty);
    BIO_free(membio);
    membio = NULL;

    /* Test flag: XN_FLAG_RFC2253 */
    ExpectNotNull(membio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                XN_FLAG_RFC2253), WOLFSSL_SUCCESS);
    BIO_free(membio);
    membio = NULL;

    /* Test flag: XN_FLAG_RFC2253 | XN_FLAG_DN_REV */
    ExpectNotNull(membio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                XN_FLAG_RFC2253 | XN_FLAG_DN_REV), WOLFSSL_SUCCESS);
    BIO_free(membio);
    membio = NULL;

    X509_free(x509);
    BIO_free(bio);
    name = NULL;

    /* Test with empty issuer cert empty-issuer-cert.pem.
     * See notes in certs/test/gen-testcerts.sh for how it was generated. */
    ExpectNotNull(bio = BIO_new(BIO_s_file()));
    ExpectIntGT(BIO_read_filename(bio, noIssuerCertFile), 0);
    ExpectNotNull(PEM_read_bio_X509(bio, &x509, NULL, NULL));
    ExpectNotNull(name = X509_get_subject_name(x509));

    ExpectNotNull(membio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(X509_NAME_print_ex(membio, name, 0, 0), WOLFSSL_SUCCESS);
    /* Should be empty string "" */
    ExpectIntEQ((memSz = BIO_get_mem_data(membio, &mem)), 0);

    BIO_free(membio);
    membio = NULL;
    X509_free(x509);
    BIO_free(bio);
    name = NULL;

    /* Test normal case without escaped characters */
    {
        /* Create name: "/C=US/CN=wolfssl.com" */
        ExpectNotNull(name = X509_NAME_new());
        ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName",
                    MBSTRING_UTF8, (byte*)"US", 2, -1, 0),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName",
                    MBSTRING_UTF8, (byte*)"wolfssl.com", 11, -1, 0),
                    WOLFSSL_SUCCESS);

        /* Test without flags */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0, 0), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expNormal));
        ExpectIntEQ(XSTRNCMP((char*)mem, expNormal, XSTRLEN(expNormal)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test with XN_FLAG_ONELINE which should enable XN_FLAG_SPC_EQ for
           spaces around '=' */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0, XN_FLAG_ONELINE),
            WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expEqSpace));
        ExpectIntEQ(XSTRNCMP((char*)mem, expEqSpace, XSTRLEN(expEqSpace)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_RFC2253 - should be reversed */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_RFC2253), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expReverse));
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_DN_REV - reversed */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_DN_REV), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expReverse));
        ExpectIntEQ(XSTRNCMP((char*)mem, expReverse, XSTRLEN(expReverse)), 0);
        BIO_free(membio);
        membio = NULL;

        X509_NAME_free(name);
        name = NULL;
    }

    /* Test RFC2253 characters are escaped with backslashes */
    {
        ExpectNotNull(name = X509_NAME_new());
        ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "countryName",
                    /* space at beginning and end, and: ,+"\ */
                    MBSTRING_UTF8, (byte*)" US,+\"\\ ", 8, -1, 0),
                    WOLFSSL_SUCCESS);
        ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName",
                    /* # at beginning, and: <>;*/
                    MBSTRING_UTF8, (byte*)"#wolfssl.com<>;", 15, -1, 0),
                    WOLFSSL_SUCCESS);
        /* Test without flags */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0, 0), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expNotEscaped));
        ExpectIntEQ(XSTRNCMP((char*)mem, expNotEscaped,
                    XSTRLEN(expNotEscaped)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_RFC5523 - should be reversed and escaped */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_RFC2253), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expRFC5523));
        ExpectIntEQ(XSTRNCMP((char*)mem, expRFC5523, XSTRLEN(expRFC5523)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_DN_REV - reversed but not escaped */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_DN_REV), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expNotEscapedRev));
        ExpectIntEQ(XSTRNCMP((char*)mem, expNotEscapedRev,
                    XSTRLEN(expNotEscapedRev)), 0);
        BIO_free(membio);

        X509_NAME_free(name);
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_NAME_ENTRY(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(NO_RSA) && defined(WOLFSSL_CERT_GEN)
    X509*      x509 = NULL;
#ifndef NO_BIO
    X509*      empty = NULL;
    BIO*       bio = NULL;
#endif
    X509_NAME* nm = NULL;
    X509_NAME_ENTRY* entry = NULL;
    WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* entries = NULL;
    unsigned char cn[] = "another name to add";
#ifdef OPENSSL_ALL
    int i;
    int names_len = 0;
#endif

    ExpectNotNull(x509 =
            wolfSSL_X509_load_certificate_file(cliCertFile, SSL_FILETYPE_PEM));
#ifndef NO_BIO
    ExpectNotNull(empty = wolfSSL_X509_new());
    ExpectNotNull(bio = BIO_new(BIO_s_mem()));
    ExpectIntEQ(PEM_write_bio_X509_AUX(NULL, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(PEM_write_bio_X509_AUX(bio, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(PEM_write_bio_X509_AUX(NULL, x509), WOLFSSL_FAILURE);
    ExpectIntEQ(PEM_write_bio_X509_AUX(bio, empty), WOLFSSL_FAILURE);
    ExpectIntEQ(PEM_write_bio_X509_AUX(bio, x509), SSL_SUCCESS);
    wolfSSL_X509_free(empty);
#endif

#ifdef WOLFSSL_CERT_REQ
    {
        X509_REQ* req = NULL;
#ifndef NO_BIO
        X509_REQ* emptyReq = NULL;
        BIO*      bReq = NULL;
#endif

        ExpectNotNull(req =
            wolfSSL_X509_load_certificate_file(cliCertFile, SSL_FILETYPE_PEM));
#ifndef NO_BIO
        ExpectNotNull(emptyReq = wolfSSL_X509_REQ_new());
        ExpectNotNull(bReq = BIO_new(BIO_s_mem()));
        ExpectIntEQ(PEM_write_bio_X509_REQ(NULL, NULL), WOLFSSL_FAILURE);
        ExpectIntEQ(PEM_write_bio_X509_REQ(bReq, NULL), WOLFSSL_FAILURE);
        ExpectIntEQ(PEM_write_bio_X509_REQ(NULL, req), WOLFSSL_FAILURE);
        ExpectIntEQ(PEM_write_bio_X509_REQ(bReq, emptyReq), WOLFSSL_FAILURE);
        ExpectIntEQ(PEM_write_bio_X509_REQ(bReq, req), SSL_SUCCESS);

        BIO_free(bReq);
        X509_REQ_free(emptyReq);
#endif
        X509_free(req);
    }
#endif

    ExpectNotNull(nm = X509_get_subject_name(x509));

    /* Test add entry */
    ExpectNotNull(entry = X509_NAME_ENTRY_create_by_NID(NULL, NID_commonName,
                0x0c, cn, (int)sizeof(cn)));
    ExpectIntEQ(X509_NAME_add_entry(nm, entry, -1, 0), SSL_SUCCESS);

    /* @TODO the internal name entry set value needs investigated for matching
     * behavior with OpenSSL. At the moment the getter function for the set
     * value is being tested only in that it succeeds in getting the internal
     * value. */
    ExpectIntGT(X509_NAME_ENTRY_set(X509_NAME_get_entry(nm, 1)), 0);

#ifdef WOLFSSL_CERT_EXT
    ExpectIntEQ(X509_NAME_add_entry_by_txt(NULL, NULL, MBSTRING_UTF8,
        (byte*)"support@wolfssl.com", 19, -1, 1), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(nm, NULL, MBSTRING_UTF8,
        (byte*)"support@wolfssl.com", 19, -1, 1), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(NULL, "emailAddress", MBSTRING_UTF8,
        (byte*)"support@wolfssl.com", 19, -1, 1), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(nm, "emailAddress", MBSTRING_UTF8,
        (byte*)"support@wolfssl.com", 19, -1, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_txt(nm, "commonName", MBSTRING_UTF8,
        (byte*)"wolfssl.com", 11, 0, 1), WOLFSSL_SUCCESS);
    ExpectNull(wolfSSL_X509_NAME_delete_entry(NULL, -1));
    ExpectNull(wolfSSL_X509_NAME_delete_entry(nm, -1));
    ExpectNotNull(wolfSSL_X509_NAME_delete_entry(nm, 0));
#endif
    X509_NAME_ENTRY_free(entry);
    entry = NULL;

#ifdef WOLFSSL_CERT_REQ
    {
        unsigned char srv_pkcs9p[] = "Server";
        unsigned char rfc822Mlbx[] = "support@wolfssl.com";
        unsigned char fvrtDrnk[] = "tequila";
        unsigned char* der = NULL;
        char* subject = NULL;

        ExpectIntEQ(X509_NAME_add_entry_by_NID(nm, NID_pkcs9_contentType,
            MBSTRING_ASC, srv_pkcs9p, -1, -1, 0), SSL_SUCCESS);

        ExpectIntEQ(X509_NAME_add_entry_by_NID(nm, NID_rfc822Mailbox,
            MBSTRING_ASC, rfc822Mlbx, -1, -1, 0), SSL_SUCCESS);

        ExpectIntEQ(X509_NAME_add_entry_by_NID(nm, NID_favouriteDrink,
            MBSTRING_ASC, fvrtDrnk, -1, -1, 0), SSL_SUCCESS);

        ExpectIntEQ(wolfSSL_i2d_X509_NAME(NULL, &der), BAD_FUNC_ARG);
        ExpectIntGT(wolfSSL_i2d_X509_NAME(nm, &der), 0);
        ExpectNotNull(der);

        ExpectNotNull(subject = X509_NAME_oneline(nm, NULL, 0));
        ExpectNotNull(XSTRSTR(subject, "rfc822Mailbox=support@wolfssl.com"));
        ExpectNotNull(XSTRSTR(subject, "favouriteDrink=tequila"));
        ExpectNotNull(XSTRSTR(subject, "contentType=Server"));
    #ifdef DEBUG_WOLFSSL
        if (subject != NULL) {
            fprintf(stderr, "\n\t%s\n", subject);
        }
    #endif
        XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    }
#endif

    ExpectNull(entry = X509_NAME_ENTRY_create_by_txt(NULL, NULL, 0x0c, cn,
        (int)sizeof(cn)));
    /* Test add entry by text */
    ExpectNotNull(entry = X509_NAME_ENTRY_create_by_txt(NULL, "commonName",
                0x0c, cn, (int)sizeof(cn)));
    ExpectPtrEq(X509_NAME_ENTRY_create_by_txt(&entry, "commonName",
                0x0c, cn, (int)sizeof(cn)), entry);
    #if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) \
    || defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX)
    ExpectNull(X509_NAME_ENTRY_create_by_txt(&entry, "unknown",
                V_ASN1_UTF8STRING, cn, (int)sizeof(cn)));
    #endif
    ExpectIntEQ(X509_NAME_add_entry(nm, entry, -1, 0), SSL_SUCCESS);
    X509_NAME_ENTRY_free(entry);
    entry = NULL;

    /* Test add entry by NID */
    ExpectIntEQ(X509_NAME_add_entry_by_NID(nm, NID_commonName, MBSTRING_UTF8,
                                       cn, -1, -1, 0), SSL_SUCCESS);

#ifdef OPENSSL_ALL
    /* stack of name entry */
    ExpectIntGT((names_len = sk_X509_NAME_ENTRY_num(nm->entries)), 0);
    for (i = 0; i < names_len; i++) {
        ExpectNotNull(entry = sk_X509_NAME_ENTRY_value(nm->entries, i));
    }
#endif

    ExpectNotNull(entries = wolfSSL_sk_X509_NAME_ENTRY_new(NULL));
    ExpectIntEQ(sk_X509_NAME_ENTRY_num(NULL), BAD_FUNC_ARG);
    ExpectIntEQ(sk_X509_NAME_ENTRY_num(entries), 0);
    ExpectNull(sk_X509_NAME_ENTRY_value(NULL, 0));
    ExpectNull(sk_X509_NAME_ENTRY_value(entries, 0));
    wolfSSL_sk_X509_NAME_ENTRY_free(entries);
#ifndef NO_BIO
    BIO_free(bio);
#endif
    X509_free(x509); /* free's nm */
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_NAME_ENTRY_get_object(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM) && !defined(NO_RSA)
    X509 *x509 = NULL;
    X509_NAME* name = NULL;
    int idx = 0;
    X509_NAME_ENTRY *ne = NULL;
    ASN1_OBJECT *object = NULL;

    ExpectNotNull(x509 = wolfSSL_X509_load_certificate_file(cliCertFile,
        WOLFSSL_FILETYPE_PEM));
    ExpectNotNull(name = X509_get_subject_name(x509));
    ExpectIntGE(X509_NAME_get_index_by_NID(NULL, NID_commonName, -1),
        BAD_FUNC_ARG);
    ExpectIntGE(idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1), 0);
    ExpectIntGE(idx = X509_NAME_get_index_by_NID(name, NID_commonName, -2), 0);

    ExpectNotNull(ne = X509_NAME_get_entry(name, idx));
    ExpectNull(X509_NAME_ENTRY_get_object(NULL));
    ExpectNotNull(object = X509_NAME_ENTRY_get_object(ne));

    X509_free(x509);
#endif
    return EXPECT_RESULT();
}

