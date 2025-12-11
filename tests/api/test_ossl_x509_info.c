/* test_ossl_x509_info.c
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
#include <tests/api/api.h>
#include <tests/api/test_ossl_x509_info.h>

int test_wolfSSL_X509_INFO_multiple_info(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_RSA) && !defined(NO_BIO)
    STACK_OF(X509_INFO) *info_stack = NULL;
    X509_INFO *info = NULL;
    int len;
    int i;
    const char* files[] = {
        cliCertFile,
        cliKeyFile,
        /* This needs to be the order as svrCertFile contains the
         * intermediate cert as well. */
        svrKeyFile,
        svrCertFile,
        NULL,
    };
    const char** curFile;
    BIO *fileBIO = NULL;
    BIO *concatBIO = NULL;
    byte tmp[FOURK_BUF];

    /* concatenate the cert and the key file to force PEM_X509_INFO_read_bio
     * to group objects together. */
    ExpectNotNull(concatBIO = BIO_new(BIO_s_mem()));
    for (curFile = files; EXPECT_SUCCESS() && *curFile != NULL; curFile++) {
        int fileLen = 0;
        ExpectNotNull(fileBIO = BIO_new_file(*curFile, "rb"));
        ExpectIntGT(fileLen = wolfSSL_BIO_get_len(fileBIO), 0);
        if (EXPECT_SUCCESS()) {
            while ((len = BIO_read(fileBIO, tmp, sizeof(tmp))) > 0) {
                ExpectIntEQ(BIO_write(concatBIO, tmp, len), len);
                fileLen -= len;
                if (EXPECT_FAIL())
                    break;
            }
            /* Make sure we read the entire file */
            ExpectIntEQ(fileLen, 0);
        }
        BIO_free(fileBIO);
        fileBIO = NULL;
    }

    ExpectNotNull(info_stack = PEM_X509_INFO_read_bio(concatBIO, NULL, NULL,
        NULL));
    ExpectIntEQ(sk_X509_INFO_num(info_stack), 3);
    for (i = 0; i < sk_X509_INFO_num(info_stack); i++) {
        ExpectNotNull(info = sk_X509_INFO_value(info_stack, i));
        ExpectNotNull(info->x509);
        ExpectNull(info->crl);
        if (i != 2) {
            ExpectNotNull(info->x_pkey);
            ExpectIntEQ(X509_check_private_key(info->x509,
                                               info->x_pkey->dec_pkey), 1);
        }
        else {
            ExpectNull(info->x_pkey);
        }
    }

    sk_X509_INFO_pop_free(info_stack, X509_INFO_free);
    BIO_free(concatBIO);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_INFO(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_RSA) && !defined(NO_BIO)
    STACK_OF(X509_INFO) *info_stack = NULL;
    X509_INFO *info = NULL;
    BIO *cert = NULL;
    int i;
    /* PEM in hex format to avoid null terminator */
    byte data[] = {
        0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47,
        0x49, 0x4e, 0x20, 0x43, 0x45, 0x52, 0x54, 0x63, 0x2d, 0x2d, 0x2d, 0x2d,
        0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x44, 0x4d, 0x54, 0x42, 0x75, 0x51, 0x3d,
        0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x2d, 0x2d,
        0x2d, 0x2d, 0x2d
    };
    /* PEM in hex format to avoid null terminator */
    byte data2[] = {
        0x41, 0x53, 0x4e, 0x31, 0x20, 0x4f, 0x49, 0x44, 0x3a, 0x20, 0x70, 0x72,
        0x69, 0x6d, 0x65, 0x32, 0x35, 0x36, 0x76, 0x31, 0x0a, 0x2d, 0x2d, 0x2d,
        0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x43, 0x20, 0x50,
        0x41, 0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x2d, 0x2d, 0x2d,
        0x2d, 0x43, 0x65, 0x72, 0x74, 0x69, 0x2d, 0x0a, 0x42, 0x67, 0x67, 0x71,
        0x68, 0x6b, 0x6a, 0x4f, 0x50, 0x51, 0x4d, 0x42, 0x42, 0x77, 0x3d, 0x3d,
        0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d
    };

    ExpectNotNull(cert = BIO_new_file(cliCertFileExt, "rb"));
    ExpectNotNull(info_stack = PEM_X509_INFO_read_bio(cert, NULL, NULL, NULL));
    for (i = 0; i < sk_X509_INFO_num(info_stack); i++) {
        ExpectNotNull(info = sk_X509_INFO_value(info_stack, i));
        ExpectNotNull(info->x509);
        ExpectNull(info->crl);
        ExpectNull(info->x_pkey);
    }
    sk_X509_INFO_pop_free(info_stack, X509_INFO_free);
    info_stack = NULL;
    BIO_free(cert);
    cert = NULL;

    ExpectNotNull(cert = BIO_new_file(cliCertFileExt, "rb"));
    ExpectNotNull(info_stack = PEM_X509_INFO_read_bio(cert, NULL, NULL, NULL));
    sk_X509_INFO_pop_free(info_stack, X509_INFO_free);
    info_stack = NULL;
    BIO_free(cert);
    cert = NULL;

    /* This case should fail due to invalid input. */
    ExpectNotNull(cert = BIO_new(BIO_s_mem()));
    ExpectIntEQ(BIO_write(cert, data, sizeof(data)), sizeof(data));
    ExpectNull(info_stack = PEM_X509_INFO_read_bio(cert, NULL, NULL, NULL));
    sk_X509_INFO_pop_free(info_stack, X509_INFO_free);
    info_stack = NULL;
    BIO_free(cert);
    cert = NULL;
    ExpectNotNull(cert = BIO_new(BIO_s_mem()));
    ExpectIntEQ(BIO_write(cert, data2, sizeof(data2)), sizeof(data2));
    ExpectNull(info_stack = PEM_X509_INFO_read_bio(cert, NULL, NULL, NULL));
    sk_X509_INFO_pop_free(info_stack, X509_INFO_free);
    BIO_free(cert);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_X509_INFO_read_bio(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    !defined(NO_BIO)
    BIO* bio = NULL;
    X509_INFO* info = NULL;
    STACK_OF(X509_INFO)* sk = NULL;
    STACK_OF(X509_INFO)* sk2 = NULL;
    char* subject = NULL;
    char exp1[] = "/C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting/"
                  "CN=www.wolfssl.com/emailAddress=info@wolfssl.com";
    char exp2[] = "/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support/"
                  "CN=www.wolfssl.com/emailAddress=info@wolfssl.com";

    ExpectNotNull(bio = BIO_new(BIO_s_file()));
    ExpectIntGT(BIO_read_filename(bio, svrCertFile), 0);
    ExpectNotNull(sk = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL));
    ExpectIntEQ(sk_X509_INFO_num(sk), 2);

    /* using dereference to maintain testing for Apache port*/
    ExpectNull(sk_X509_INFO_pop(NULL));
    ExpectNotNull(info = sk_X509_INFO_pop(sk));
    ExpectNotNull(subject = X509_NAME_oneline(X509_get_subject_name(info->x509),
        0, 0));

    ExpectIntEQ(0, XSTRNCMP(subject, exp1, sizeof(exp1)));
    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
    subject = NULL;
    X509_INFO_free(info);
    info = NULL;

    ExpectNotNull(info = sk_X509_INFO_pop(sk));
    ExpectNotNull(subject = X509_NAME_oneline(X509_get_subject_name(info->x509),
        0, 0));

    ExpectIntEQ(0, XSTRNCMP(subject, exp2, sizeof(exp2)));
    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
    subject = NULL;
    X509_INFO_free(info);
    ExpectNull(info = sk_X509_INFO_pop(sk));

    sk_X509_INFO_pop_free(sk, X509_INFO_free);
    sk = NULL;
    BIO_free(bio);
    bio = NULL;

    ExpectNotNull(sk = wolfSSL_sk_X509_INFO_new_null());
    ExpectNotNull(bio = BIO_new(BIO_s_file()));
    ExpectIntGT(BIO_read_filename(bio, svrCertFile), 0);
    ExpectNotNull(sk2 = PEM_X509_INFO_read_bio(bio, sk, NULL, NULL));
    ExpectPtrEq(sk, sk2);
    if (sk2 != sk) {
        sk_X509_INFO_pop_free(sk, X509_INFO_free);
    }
    sk = NULL;
    BIO_free(bio);
    sk_X509_INFO_pop_free(sk2, X509_INFO_free);

    ExpectNotNull(sk = wolfSSL_sk_X509_INFO_new_null());
    sk_X509_INFO_free(sk);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_PEM_X509_INFO_read(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    !defined(NO_BIO)
    XFILE fp = XBADFILE;
    STACK_OF(X509_INFO)* sk = NULL;

    ExpectTrue((fp = XFOPEN(svrCertFile, "rb")) != XBADFILE);
    ExpectNull(wolfSSL_PEM_X509_INFO_read(XBADFILE, NULL, NULL, NULL));
    ExpectNotNull(sk = wolfSSL_PEM_X509_INFO_read(fp, NULL, NULL, NULL));

    sk_X509_INFO_pop_free(sk, X509_INFO_free);
    if (fp != XBADFILE)
        XFCLOSE(fp);
#endif
    return EXPECT_RESULT();
}

