/* test_ossl_x509_name.c
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
    ExpectIntEQ(X509_NAME_hash(X509_get_subject_name(x509)), 0x6903FF67);
    ExpectIntEQ(X509_NAME_hash(X509_get_issuer_name(x509)), 0xB59C2F94);
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
    const char* expRFC2253 = "CN=wolfssl.com,C=US";
    const char* expMultiline =
        "countryName               = US\n"
        "commonName                = wolfssl.com";
    const char* expMultilineInd =
        "  countryName               = US\n"
        "  commonName                = wolfssl.com";
    const char* expSemi = "C=US; CN=wolfssl.com";
    const char* expNoName = "US, wolfssl.com";
    const char* expLongName = "countryName=US, commonName=wolfssl.com";
    const char* expAligned = "C         =US, CN        =wolfssl.com";
    const char* expIndent = "   C=US, CN=wolfssl.com";

    const char* expNotEscaped = "C= US,+\"\\ , CN=#wolfssl.com<>;";
    const char* expNotEscapedRev = "CN=#wolfssl.com<>;, C= US,+\"\\ ";
    const char* expRFC2253Esc =
        "CN=\\#wolfssl.com\\<\\>\\;,C=\\ US\\,\\+\\\"\\\\\\ ";
    const char* expEscaped =
        "C=\\ US\\,\\+\\\"\\\\\\ , CN=\\#wolfssl.com\\<\\>\\;";
    const char* expEscapedComma =
        "C=\\ US\\,\\+\\\"\\\\\\ ,CN=\\#wolfssl.com\\<\\>\\;";
    const unsigned char valNul[] = "with\0null";
    const unsigned char expNul[] = "CN=with\0null";
    const char* expNulCtrl = "CN=with\\00null";
    const unsigned char valBs[] = "a\\b";
    const char* expBsCtrl = "CN=a\\\\b";
    const unsigned char valMsb[] = "\xC3\xA9";
    const char* expMsb = "CN=\\C3\\A9";
    const char* expSpace = "CN=\\ ";

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

        /* Test flags: XN_FLAG_RFC2253 - reversed, comma separated */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_RFC2253), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expRFC2253));
        ExpectIntEQ(XSTRNCMP((char*)mem, expRFC2253, XSTRLEN(expRFC2253)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_MULTILINE - one entry per line, long names
         * aligned, spaces around '=' */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0, XN_FLAG_MULTILINE),
            WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expMultiline));
        ExpectIntEQ(XSTRNCMP((char*)mem, expMultiline, XSTRLEN(expMultiline)),
            0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_MULTILINE with indent - every line indented */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 2, XN_FLAG_MULTILINE),
            WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expMultilineInd));
        ExpectIntEQ(XSTRNCMP((char*)mem, expMultilineInd,
            XSTRLEN(expMultilineInd)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_SEP_SPLUS_SPC */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_SEP_SPLUS_SPC | ASN1_STRFLGS_ESC_2253 |
                    ASN1_STRFLGS_UTF8_CONVERT), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expSemi));
        ExpectIntEQ(XSTRNCMP((char*)mem, expSemi, XSTRLEN(expSemi)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_FN_NONE */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_NONE |
                    ASN1_STRFLGS_UTF8_CONVERT), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expNoName));
        ExpectIntEQ(XSTRNCMP((char*)mem, expNoName, XSTRLEN(expNoName)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_FN_LN */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_LN |
                    ASN1_STRFLGS_UTF8_CONVERT), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expLongName));
        ExpectIntEQ(XSTRNCMP((char*)mem, expLongName, XSTRLEN(expLongName)),
            0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_FN_SN | XN_FLAG_FN_ALIGN */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN | XN_FLAG_FN_ALIGN |
                    ASN1_STRFLGS_UTF8_CONVERT), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expAligned));
        ExpectIntEQ(XSTRNCMP((char*)mem, expAligned, XSTRLEN(expAligned)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test indent without XN_FLAG_SEP_MULTILINE - only the first line */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 3,
                    XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_UTF8_CONVERT),
                    WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expIndent));
        ExpectIntEQ(XSTRNCMP((char*)mem, expIndent, XSTRLEN(expIndent)), 0);
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

        /* Test flags: XN_FLAG_RFC2253 - reversed, escaped, comma separated */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_RFC2253), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expRFC2253Esc));
        ExpectIntEQ(XSTRNCMP((char*)mem, expRFC2253Esc,
            XSTRLEN(expRFC2253Esc)), 0);
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
        membio = NULL;

        /* Test flags: ASN1_STRFLGS_ESC_2253 - escaped but not reversed.
         * Flags as used by OpenVPN. */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN |
                    ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_UTF8_CONVERT),
                    WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expEscaped));
        ExpectIntEQ(XSTRNCMP((char*)mem, expEscaped, XSTRLEN(expEscaped)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_RFC2253 without XN_FLAG_DN_REV - escaped but
         * not reversed */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_RFC2253 & ~XN_FLAG_DN_REV), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expEscapedComma));
        ExpectIntEQ(XSTRNCMP((char*)mem, expEscapedComma,
            XSTRLEN(expEscapedComma)), 0);
        BIO_free(membio);
        membio = NULL;

        X509_NAME_free(name);
        name = NULL;
    }

    /* Test NUL, control and non-ASCII bytes in values */
    {
        ExpectNotNull(name = X509_NAME_new());
        ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName",
                    MBSTRING_UTF8, valNul, sizeof(valNul) - 1, -1, 0),
                    WOLFSSL_SUCCESS);

        /* Test without flags - NUL byte is written as is. OpenSSL falls
         * back to X509_NAME_print() here and escapes it. */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0, 0), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, sizeof(expNul) - 1);
        ExpectIntEQ(XMEMCMP(mem, expNul, sizeof(expNul) - 1), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: ASN1_STRFLGS_ESC_2253 - NUL byte is written as is */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN |
                    ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_UTF8_CONVERT),
                    WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, sizeof(expNul) - 1);
        ExpectIntEQ(XMEMCMP(mem, expNul, sizeof(expNul) - 1), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: ASN1_STRFLGS_ESC_CTRL - NUL byte is escaped */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_ESC_CTRL |
                    ASN1_STRFLGS_UTF8_CONVERT), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expNulCtrl));
        ExpectIntEQ(XSTRNCMP((char*)mem, expNulCtrl, XSTRLEN(expNulCtrl)), 0);
        BIO_free(membio);
        membio = NULL;

        X509_NAME_free(name);
        name = NULL;

        /* Backslash is escaped whenever any escaping is done */
        ExpectNotNull(name = X509_NAME_new());
        ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName",
                    MBSTRING_UTF8, valBs, sizeof(valBs) - 1, -1, 0),
                    WOLFSSL_SUCCESS);
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_ESC_CTRL |
                    ASN1_STRFLGS_UTF8_CONVERT), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expBsCtrl));
        ExpectIntEQ(XSTRNCMP((char*)mem, expBsCtrl, XSTRLEN(expBsCtrl)), 0);
        BIO_free(membio);
        membio = NULL;
        X509_NAME_free(name);
        name = NULL;

        ExpectNotNull(name = X509_NAME_new());
        ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName",
                    MBSTRING_UTF8, valMsb, sizeof(valMsb) - 1, -1, 0),
                    WOLFSSL_SUCCESS);

        /* Test without flags - non-ASCII bytes are written as is */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0, 0), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, 3 + sizeof(valMsb) - 1);
        ExpectIntEQ(XMEMCMP(mem + 3, valMsb, sizeof(valMsb) - 1), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: ASN1_STRFLGS_ESC_MSB - non-ASCII bytes are escaped */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_ESC_MSB |
                    ASN1_STRFLGS_UTF8_CONVERT), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expMsb));
        ExpectIntEQ(XSTRNCMP((char*)mem, expMsb, XSTRLEN(expMsb)), 0);
        BIO_free(membio);
        membio = NULL;

        /* Test flags: XN_FLAG_RFC2253 - includes ASN1_STRFLGS_ESC_MSB */
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_RFC2253), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expMsb));
        ExpectIntEQ(XSTRNCMP((char*)mem, expMsb, XSTRLEN(expMsb)), 0);
        BIO_free(membio);
        membio = NULL;
        X509_NAME_free(name);
        name = NULL;

        /* A lone space is both a leading and a trailing space */
        ExpectNotNull(name = X509_NAME_new());
        ExpectIntEQ(X509_NAME_add_entry_by_txt(name, "commonName",
                    MBSTRING_UTF8, (const byte*)" ", 1, -1, 0),
                    WOLFSSL_SUCCESS);
        ExpectNotNull(membio = BIO_new(BIO_s_mem()));
        ExpectIntEQ(X509_NAME_print_ex(membio, name, 0,
                    XN_FLAG_SEP_CPLUS_SPC | ASN1_STRFLGS_ESC_2253 |
                    ASN1_STRFLGS_UTF8_CONVERT), WOLFSSL_SUCCESS);
        ExpectIntGE((memSz = BIO_get_mem_data(membio, &mem)), 0);
        ExpectIntEQ(memSz, XSTRLEN(expSpace));
        ExpectIntEQ(XSTRNCMP((char*)mem, expSpace, XSTRLEN(expSpace)), 0);
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


/* X509_NAME_oneline() must escape the '/' RDN separator and the '+'
 * multi-valued RDN separator when they appear inside an attribute value, as
 * OpenSSL 3 does. Otherwise a single attribute whose value contains them
 * (CN="foo/O=bar") renders byte-identical to a name made of several
 * attributes (CN=foo, O=bar) and the two are indistinguishable to callers
 * that compare the one-line form (wolfSSL/wolfssl#11392). The same flat
 * string backs X509_NAME_cmp() and X509_check_issued().
 *
 * Unlike OpenSSL, a '\' inside a value is escaped as well. Otherwise
 * CN="foo\", O=bar still renders as CN="foo/O=bar" does, and CN="a\+b" as
 * CN="a+b" does, and wolfSSL compares names by this string. */
int test_wolfSSL_X509_NAME_oneline_escape(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_CERTS)
    X509_NAME* nameA = NULL;    /* one RDN:  CN="foo/O=bar"           */
    X509_NAME* nameB = NULL;    /* two RDNs: CN=foo, O=bar            */
    X509_NAME* namePlus = NULL; /* one RDN:  CN="a+b"                 */
    X509_NAME* nameBackslash = NULL; /* one RDN:  CN="a\+b"           */
    X509_NAME* nameTrail = NULL; /* two RDNs: CN="foo\", O=bar        */
    X509_NAME* nameLong = NULL; /* one RDN:  CN=<399 +'s>             */
    static byte longName[400];
    char* onelineA = NULL;
    char* onelineB = NULL;
    char* onelinePlus = NULL;
    char* onelineBackslash = NULL;
    char* onelineTrail = NULL;
    char* onelineLong = NULL;
    const char* expA = "/CN=foo\\/O=bar";
    const char* expB = "/CN=foo/O=bar";
    const char* expPlus = "/CN=a\\+b";
    const char* expBackslash = "/CN=a\\\\\\+b";
    const char* expTrail = "/CN=foo\\\\/O=bar";

    /* load characters into long name */
    XMEMSET((char*)longName, '+', sizeof(longName) - 1);

    ExpectNotNull(nameA = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_NID(nameA, NID_commonName,
        MBSTRING_UTF8, (const byte*)"foo/O=bar", 9, -1, 0), WOLFSSL_SUCCESS);

    ExpectNotNull(nameB = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_NID(nameB, NID_commonName,
        MBSTRING_UTF8, (const byte*)"foo", 3, -1, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_NID(nameB, NID_organizationName,
        MBSTRING_UTF8, (const byte*)"bar", 3, -1, 0), WOLFSSL_SUCCESS);

    ExpectNotNull(namePlus = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_NID(namePlus, NID_commonName,
        MBSTRING_UTF8, (const byte*)"a+b", 3, -1, 0), WOLFSSL_SUCCESS);

    ExpectNotNull(nameBackslash = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_NID(nameBackslash,
                NID_commonName, MBSTRING_UTF8,
                (const byte*)"a\\+b", 4, -1, 0), WOLFSSL_SUCCESS);

    ExpectNotNull(nameTrail = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_NID(nameTrail, NID_commonName,
        MBSTRING_UTF8, (const byte*)"foo\\", 4, -1, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(X509_NAME_add_entry_by_NID(nameTrail, NID_organizationName,
        MBSTRING_UTF8, (const byte*)"bar", 3, -1, 0), WOLFSSL_SUCCESS);

    ExpectNotNull(nameLong = X509_NAME_new());
    ExpectIntEQ(X509_NAME_add_entry_by_NID(nameLong, NID_commonName,
                MBSTRING_UTF8, longName, sizeof(longName) - 1, -1, 0),
                WOLFSSL_SUCCESS);

    /* Names built from entries. Sanity check first: a name without special
     * characters in its values is rendered as before. */
    ExpectNotNull(onelineB = X509_NAME_oneline(nameB, NULL, 0));
    ExpectStrEQ(onelineB, expB);

    /* A '/' inside a value is escaped and the two names differ. */
    ExpectNotNull(onelineA = X509_NAME_oneline(nameA, NULL, 0));
    ExpectStrEQ(onelineA, expA);
    ExpectIntNE(X509_NAME_cmp(nameA, nameB), 0);

    /* A '+' inside a value is escaped. */
    ExpectNotNull(onelinePlus = X509_NAME_oneline(namePlus, NULL, 0));
    ExpectStrEQ(onelinePlus, expPlus);

    /* A backslash in a value is data, not an escape: CN="a\+b" must not
     * render or compare the same as CN="a+b". */
    ExpectNotNull(onelineBackslash =
            X509_NAME_oneline(nameBackslash, NULL, 0));
    ExpectStrEQ(onelineBackslash, expBackslash);
    ExpectIntNE(X509_NAME_cmp(namePlus, nameBackslash), 0);

    /* A trailing backslash must not escape the following separator. */
    ExpectNotNull(onelineTrail = X509_NAME_oneline(nameTrail, NULL, 0));
    ExpectStrEQ(onelineTrail, expTrail);
    ExpectIntNE(X509_NAME_cmp(nameA, nameTrail), 0);

    /* Every character of the long value is escaped. */
    ExpectNotNull(onelineLong = X509_NAME_oneline(nameLong, NULL, 0));
    if (EXPECT_SUCCESS()) {
        int i;
        int len;
        const char* val = onelineLong + XSTRLEN("/CN=");

        ExpectIntEQ(XSTRNCMP(onelineLong, "/CN=", XSTRLEN("/CN=")), 0);
        len = (int)XSTRLEN(val);
        ExpectIntEQ(len, (sizeof(longName) - 1) * 2);
        for (i = 0; EXPECT_SUCCESS() && (i + 1 < len); i += 2) {
            ExpectIntEQ(val[i], '\\');
            ExpectIntEQ(val[i + 1], '+');
        }
    }

    /* A duplicated name has its one-line form rebuilt from the raw entry
     * values, so it must come out identical and not be escaped twice. */
    {
        X509_NAME* orig[6];
        int i;

        orig[0] = nameA;
        orig[1] = nameB;
        orig[2] = namePlus;
        orig[3] = nameBackslash;
        orig[4] = nameTrail;
        orig[5] = nameLong;

        for (i = 0; i < (int)(sizeof(orig) / sizeof(*orig)); i++) {
            X509_NAME* dup = NULL;
            X509_NAME* dupDup = NULL;
            char* origLine = NULL;
            char* dupLine = NULL;

            ExpectNotNull(dup = X509_NAME_dup(orig[i]));
            ExpectNotNull(dupDup = X509_NAME_dup(dup));
            ExpectNotNull(origLine = X509_NAME_oneline(orig[i], NULL, 0));
            ExpectNotNull(dupLine = X509_NAME_oneline(dupDup, NULL, 0));
            ExpectStrEQ(dupLine, origLine);
            ExpectIntEQ(X509_NAME_cmp(orig[i], dup), 0);
            ExpectIntEQ(X509_NAME_cmp(orig[i], dupDup), 0);

            XFREE(dupLine, NULL, DYNAMIC_TYPE_OPENSSL);
            XFREE(origLine, NULL, DYNAMIC_TYPE_OPENSSL);
            X509_NAME_free(dupDup);
            X509_NAME_free(dup);
        }
    }
#if defined(WOLFSSL_CERT_GEN) && !defined(NO_RSA) && !defined(NO_SHA256) && \
    !defined(NO_ASN_TIME) && defined(USE_CERT_BUFFERS_2048)
    /* Names parsed from a certificate, as in the report: the flat string is
     * produced by the certificate parser, not by the entry functions. */
    {
        X509_NAME* names[4];
        const char* exp[4];
        char* certOneline[4] = { NULL, NULL, NULL, NULL };
        EVP_PKEY* priv = NULL;
        EVP_PKEY* pub = NULL;
        const unsigned char* keyPt = client_key_der_2048;
        const unsigned char* pubPt = client_keypub_der_2048;
        int i;

        names[0] = nameA;
        names[1] = nameB;
        names[2] = nameBackslash;
        names[3] = nameTrail;
        exp[0] = expA;
        exp[1] = expB;
        exp[2] = expBackslash;
        exp[3] = expTrail;

        ExpectNotNull(priv = wolfSSL_d2i_PrivateKey(EVP_PKEY_RSA, NULL, &keyPt,
            (long)sizeof_client_key_der_2048));
        ExpectNotNull(pub = wolfSSL_d2i_PUBKEY(NULL, &pubPt,
            (long)sizeof_client_keypub_der_2048));

        for (i = 0; i < 4; i++) {
            X509* x509 = NULL;
            X509* parsed = NULL;
            const unsigned char* der = NULL;
            int derSz = 0;
            DecodedCert dCert;

            ExpectNotNull(x509 = X509_new());
            ExpectIntNE(X509_set_version(x509, 2L), 0);
            ExpectIntEQ(X509_set_subject_name(x509, names[i]),
                WOLFSSL_SUCCESS);
            ExpectIntEQ(X509_set_issuer_name(x509, names[i]),
                WOLFSSL_SUCCESS);
            ExpectIntEQ(X509_set_pubkey(x509, pub), WOLFSSL_SUCCESS);
            ExpectIntGT(X509_sign(x509, priv, EVP_sha256()), 0);

            ExpectNotNull(der = wolfSSL_X509_get_der(x509, &derSz));

            /* The parser's own flat subject string. This is what a build
             * without OPENSSL_EXTRA hands to X509_NAME_oneline(); with
             * OPENSSL_EXTRA the X509's copy is rebuilt from the entries. */
            if ((der != NULL) && (derSz > 0)) {
                wc_InitDecodedCert(&dCert, der, (word32)derSz, NULL);
                ExpectIntEQ(wc_ParseCert(&dCert, CERT_TYPE, NO_VERIFY, NULL),
                    0);
                ExpectStrEQ(dCert.subject, exp[i]);
                ExpectStrEQ(dCert.issuer, exp[i]);
                wc_FreeDecodedCert(&dCert);
            }

            /* Re-parse the signed encoding so the subject comes from the
             * certificate parser rather than from the entries set above. */
            ExpectNotNull(parsed = d2i_X509(NULL, &der, derSz));
            ExpectNotNull(certOneline[i] = X509_NAME_oneline(
                X509_get_subject_name(parsed), NULL, 0));
            ExpectStrEQ(certOneline[i], exp[i]);

            X509_free(parsed);
            X509_free(x509);
        }

        /* The structurally different subjects must not collide with the
         * single RDN CN="foo/O=bar". */
        if (certOneline[0] != NULL && certOneline[1] != NULL) {
            ExpectIntNE(XSTRCMP(certOneline[0], certOneline[1]), 0);
        }
        if (certOneline[0] != NULL && certOneline[3] != NULL) {
            ExpectIntNE(XSTRCMP(certOneline[0], certOneline[3]), 0);
        }

        for (i = 0; i < 4; i++) {
            XFREE(certOneline[i], NULL, DYNAMIC_TYPE_OPENSSL);
        }
        EVP_PKEY_free(pub);
        EVP_PKEY_free(priv);
    }
#endif

    XFREE(onelinePlus, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(onelineBackslash, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(onelineTrail, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(onelineA, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(onelineB, NULL, DYNAMIC_TYPE_OPENSSL);
    XFREE(onelineLong, NULL, DYNAMIC_TYPE_OPENSSL);
    X509_NAME_free(namePlus);
    X509_NAME_free(nameBackslash);
    X509_NAME_free(nameTrail);
    X509_NAME_free(nameLong);
    X509_NAME_free(nameA);
    X509_NAME_free(nameB);
#endif
    return EXPECT_RESULT();
}
