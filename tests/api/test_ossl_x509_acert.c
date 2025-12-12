/* test_ossl_x509_acert.c
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
#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/pem.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_ossl_x509_acert.h>

#if defined(WOLFSSL_ACERT) && !defined(NO_CERTS) && !defined(NO_RSA) && \
    defined(WC_RSA_PSS) && !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA)
/* Given acert file and its pubkey file, read them and then
 * attempt to verify signed acert.
 *
 * If expect_pass is true, then verification should pass.
 * If expect_pass is false, then verification should fail.
 * */
static int do_acert_verify_test(const char * acert_file,
                                const char * pkey_file,
                                size_t       expect_pass)
{
    X509_ACERT * x509 = NULL;
    EVP_PKEY *   pkey = NULL;
    BIO *        bp = NULL;
    int          verify_rc = 0;

    /* First read the attribute certificate. */
    bp = BIO_new_file(acert_file, "r");
    if (bp == NULL) {
        return -1;
    }

    x509 = PEM_read_bio_X509_ACERT(bp, NULL, NULL, NULL);
    BIO_free(bp);
    bp = NULL;

    if (x509 == NULL) {
        return -1;
    }

    /* Next read the associated pub key. */
    bp = BIO_new_file(pkey_file, "r");

    if (bp == NULL) {
        X509_ACERT_free(x509);
        x509 = NULL;
        return -1;
    }

    pkey = PEM_read_bio_PUBKEY(bp, &pkey, NULL, NULL);
    BIO_free(bp);
    bp = NULL;

    if (pkey == NULL) {
        X509_ACERT_free(x509);
        x509 = NULL;
        return -1;
    }

    /* Finally, do verification. */
    verify_rc = X509_ACERT_verify(x509, pkey);

    X509_ACERT_free(x509);
    x509 = NULL;

    EVP_PKEY_free(pkey);
    pkey = NULL;

    if (expect_pass && verify_rc != 1) {
        return -1;
    }

    if (!expect_pass && verify_rc == 1) {
        return -1;
    }

    return 0;
}
#endif

int test_wolfSSL_X509_ACERT_verify(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ACERT) && !defined(NO_CERTS) && !defined(NO_RSA) && \
    defined(WC_RSA_PSS) && !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA)
    /* Walk over list of signed ACERTs and their pubkeys.
     * All should load and pass verification. */
    const char * acerts[4] = {"certs/acert/acert.pem",
                              "certs/acert/acert_ietf.pem",
                              "certs/acert/rsa_pss/acert.pem",
                              "certs/acert/rsa_pss/acert_ietf.pem"};
    const char * pkeys[4] =  {"certs/acert/acert_pubkey.pem",
                              "certs/acert/acert_ietf_pubkey.pem",
                              "certs/acert/rsa_pss/acert_pubkey.pem",
                              "certs/acert/rsa_pss/acert_ietf_pubkey.pem"};
    int    rc = 0;
    size_t i = 0;
    size_t j = 0;

    for (i = 0; i < 4; ++i) {
        for (j = i; j < 4; ++j) {
            rc = do_acert_verify_test(acerts[i], pkeys[j], i == j);

            if (rc) {
                fprintf(stderr, "error: %s: i = %zu, j = %zu, rc = %d\n",
                        "do_acert_verify_test", i, j, rc);
                break;
            }
        }

        if (rc) { break; }
    }

    ExpectIntEQ(rc, 0);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_ACERT_misc_api(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ACERT) && !defined(NO_CERTS) && !defined(NO_RSA) && \
    !defined(NO_FILESYSTEM) && defined(OPENSSL_EXTRA)
    const char * acerts[4] = {"certs/acert/acert.pem",
                              "certs/acert/acert_ietf.pem",
                              "certs/acert/rsa_pss/acert.pem",
                              "certs/acert/rsa_pss/acert_ietf.pem"};
    int          rc = 0;
    X509_ACERT * x509 = NULL;
    BIO *        bp = NULL;
    long         ver_long = 0;
    int          ver = 0;
    int          nid = 0;
    const byte * raw_attr = NULL;
    word32       attr_len = 0;
    size_t       i = 0;
    int          buf_len = 0;
    byte         ietf_serial[] = {0x03, 0xb5, 0x90, 0x59, 0x02,
                                  0xa2, 0xaa, 0xb5, 0x40, 0x21,
                                  0x44, 0xb8, 0x2c, 0x4f, 0xd9,
                                  0x80, 0x1b, 0x5f, 0x57, 0xc2};

    for (i = 0; i < 4; ++i) {
        const char * acert_file = acerts[i];
        int          is_rsa_pss = 0;
        int          is_ietf_acert = 0;
        byte         serial[64];
        int          serial_len = sizeof(serial);

        XMEMSET(serial, 0, sizeof(serial));

        is_rsa_pss = XSTRSTR(acert_file, "rsa_pss") != NULL ? 1 : 0;
        is_ietf_acert = XSTRSTR(acert_file, "ietf.pem") != NULL ? 1 : 0;

        /* First read the attribute certificate. */
        bp = BIO_new_file(acert_file, "r");
        ExpectNotNull(bp);

        x509 = PEM_read_bio_X509_ACERT(bp, NULL, NULL, NULL);
        ExpectNotNull(x509);

        /* We're done with the bio for now. */
        if (bp != NULL) {
            BIO_free(bp);
            bp = NULL;
        }

        /* Check version and signature NID. */
        ver_long = X509_ACERT_get_version(x509);
        ExpectIntEQ(ver_long, 1);

        ver = wolfSSL_X509_ACERT_version(x509);
        ExpectIntEQ(ver, 2);

        nid = X509_ACERT_get_signature_nid(x509);

        if (is_rsa_pss) {
            ExpectIntEQ(nid, NID_rsassaPss);
        }
        else {
            ExpectIntEQ(nid, NID_sha256WithRSAEncryption);
        }

        /* Get the serial number buffer.
         * The ietf acert example has a 20 byte serial number. */
        rc = wolfSSL_X509_ACERT_get_serial_number(x509, serial, &serial_len);
        ExpectIntEQ(rc, SSL_SUCCESS);

        if (is_ietf_acert) {
            ExpectIntEQ(serial_len, 20);
            ExpectIntEQ(XMEMCMP(serial, ietf_serial, sizeof(ietf_serial)), 0);
        }
        else {
            ExpectIntEQ(serial_len, 1);
            ExpectTrue(serial[0] == 0x01);
        }

        /* Repeat the same but with null serial buffer. This is ok. */
        rc = wolfSSL_X509_ACERT_get_serial_number(x509, NULL, &serial_len);
        ExpectIntEQ(rc, SSL_SUCCESS);

        if (is_ietf_acert) {
            ExpectIntEQ(serial_len, 20);
        }
        else {
            ExpectIntEQ(serial_len, 1);
            ExpectTrue(serial[0] == 0x01);
        }

        /* Get the attributes buffer. */
        rc = wolfSSL_X509_ACERT_get_attr_buf(x509, &raw_attr, &attr_len);
        ExpectIntEQ(rc, SSL_SUCCESS);

        if (is_ietf_acert) {
            /* This cert has a 65 byte attributes field. */
            ExpectNotNull(raw_attr);
            ExpectIntEQ(attr_len, 65);
        }
        else {
            /* This cert has a 237 byte attributes field. */
            ExpectNotNull(raw_attr);
            ExpectIntEQ(attr_len, 237);
        }

        /* Test printing acert to memory bio. */
        ExpectNotNull(bp = BIO_new(BIO_s_mem()));
        rc = X509_ACERT_print(bp, x509);
        ExpectIntEQ(rc, SSL_SUCCESS);

        /* Now do a bunch of invalid stuff with partially valid inputs. */
        rc = wolfSSL_X509_ACERT_get_attr_buf(x509, &raw_attr, NULL);
        ExpectIntEQ(rc, BAD_FUNC_ARG);

        rc = wolfSSL_X509_ACERT_get_attr_buf(x509, NULL, &attr_len);
        ExpectIntEQ(rc, BAD_FUNC_ARG);

        rc = wolfSSL_X509_ACERT_get_attr_buf(NULL, &raw_attr, &attr_len);
        ExpectIntEQ(rc, BAD_FUNC_ARG);

        ver_long = X509_ACERT_get_version(NULL);
        ExpectIntEQ(ver_long, 0);

        ver = wolfSSL_X509_ACERT_version(NULL);
        ExpectIntEQ(ver, 0);

        rc = wolfSSL_X509_ACERT_get_signature(x509, NULL, NULL);
        ExpectIntEQ(rc, WOLFSSL_FATAL_ERROR);

        rc = wolfSSL_X509_ACERT_get_signature(x509, NULL, &buf_len);
        ExpectIntEQ(rc, SSL_SUCCESS);
        ExpectIntEQ(buf_len, 256);

        rc = wolfSSL_X509_ACERT_get_serial_number(x509, serial, NULL);
        ExpectIntEQ(rc, BAD_FUNC_ARG);

        rc = X509_ACERT_print(bp, NULL);
        ExpectIntEQ(rc, WOLFSSL_FAILURE);

        rc = X509_ACERT_print(NULL, x509);
        ExpectIntEQ(rc, WOLFSSL_FAILURE);

        /* Finally free the acert and bio, we're done with them. */
        if (x509 != NULL) {
            X509_ACERT_free(x509);
            x509 = NULL;
        }

        if (bp != NULL) {
            BIO_free(bp);
            bp = NULL;
        }
    }
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_ACERT_buffer(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ACERT) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && defined(WC_RSA_PSS) && \
    (defined(OPENSSL_EXTRA_X509_SMALL) || defined(OPENSSL_EXTRA))
    const byte acert_ietf[] = \
    "-----BEGIN ATTRIBUTE CERTIFICATE-----\n"
    "MIICPTCCASUCAQEwN6AWMBGkDzANMQswCQYDVQQDDAJDQQIBAqEdpBswGTEXMBUG\n"
    "A1UEAwwOc2VydmVyLmV4YW1wbGWgLTArpCkwJzElMCMGA1UEAwwcQXR0cmlidXRl\n"
    "IENlcnRpZmljYXRlIElzc3VlcjANBgkqhkiG9w0BAQsFAAIUA7WQWQKiqrVAIUS4\n"
    "LE/ZgBtfV8IwIhgPMjAyMTA2MTUxMjM1MDBaGA8yMDMxMDYxMzEyMzUwMFowQTAj\n"
    "BggrBgEFBQcKBDEXMBWgCYYHVGVzdHZhbDAIDAZncm91cDEwGgYDVQRIMRMwEaEP\n"
    "gw1hZG1pbmlzdHJhdG9yMCwwHwYDVR0jBBgwFoAUYm7JaGdsZLtTgt0tqoCK2MrI\n"
    "i10wCQYDVR04BAIFADANBgkqhkiG9w0BAQsFAAOCAQEAlIOJ2Dj3TEUj6BIv6vUs\n"
    "GqFWms05i+d10XSzWrunlUTQPoJcUjYkifOWp/7RpZ2XnRl+6hH+nIbmwSmXWwBn\n"
    "ERw2bQMmw/""/nWuN4Qv9t7ltuovWC0pJX6VMT1IRTuTV4SxuZpFL37vkmnFlPBlb+\n"
    "mn3ESSxLTjThWFIq1tip4IaxE/i5Uh32GlJglatFHM1PCGoJtyLtYb6KHDlvknw6\n"
    "coDyjIcj0FZwtQw41jLwxI8jWNmrpt978wdpprB/URrRs+m02HmeQoiHFi/qvdv8\n"
    "d+5vHf3Pi/ulhz/+dvr0p1vEQSoFnYxLXuty2p5m3PJPZCFmT3gURgmgR3BN9d7A\n"
    "Bw==\n"
    "-----END ATTRIBUTE CERTIFICATE-----\n";
    X509_ACERT * x509 = NULL;
    int          rc = 0;
    byte         ietf_serial[] = {0x03, 0xb5, 0x90, 0x59, 0x02,
                                  0xa2, 0xaa, 0xb5, 0x40, 0x21,
                                  0x44, 0xb8, 0x2c, 0x4f, 0xd9,
                                  0x80, 0x1b, 0x5f, 0x57, 0xc2};
    byte         serial[64];
    int          serial_len = sizeof(serial);
    const byte * raw_attr = NULL;
    word32       attr_len = 0;

    x509 = wolfSSL_X509_ACERT_load_certificate_buffer_ex(acert_ietf,
                                                         sizeof(acert_ietf),
                                                         WOLFSSL_FILETYPE_PEM,
                                                         HEAP_HINT);

    rc = wolfSSL_X509_ACERT_get_serial_number(x509, serial, &serial_len);
    ExpectIntEQ(rc, SSL_SUCCESS);

    ExpectIntEQ(serial_len, 20);
    ExpectIntEQ(XMEMCMP(serial, ietf_serial, sizeof(ietf_serial)), 0);

    /* Get the attributes buffer. */
    rc = wolfSSL_X509_ACERT_get_attr_buf(x509, &raw_attr, &attr_len);
    ExpectIntEQ(rc, SSL_SUCCESS);

    /* This cert has a 65 byte attributes field. */
    ExpectNotNull(raw_attr);
    ExpectIntEQ(attr_len, 65);

    ExpectNotNull(x509);

    if (x509 != NULL) {
        wolfSSL_X509_ACERT_free(x509);
        x509 = NULL;
    }
#endif
    return EXPECT_RESULT();
}

/* note: when ACERT generation and signing are implemented,
 * this test will be filled out appropriately.
 * */
int test_wolfSSL_X509_ACERT_new_and_sign(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ACERT) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && defined(WC_RSA_PSS) && \
    (defined(OPENSSL_EXTRA_X509_SMALL) || defined(OPENSSL_EXTRA))
    X509_ACERT * x509 = NULL;
    int          rc = 0;

    x509 = X509_ACERT_new();
    ExpectNotNull(x509);

    if (x509 != NULL) {
        wolfSSL_X509_ACERT_free(x509);
        x509 = NULL;
    }

    /* Same but with static memory hint. */
    x509 = wolfSSL_X509_ACERT_new_ex(HEAP_HINT);
    ExpectNotNull(x509);

    #ifndef NO_WOLFSSL_STUB
    /* ACERT sign not implemented yet. */
    if (x509 != NULL) {
        rc = wolfSSL_X509_ACERT_sign(x509, NULL, NULL);
        ExpectIntEQ(rc, WOLFSSL_NOT_IMPLEMENTED);
    }
    #else
    (void) rc;
    #endif /* NO_WOLFSSL_STUB */

    if (x509 != NULL) {
        wolfSSL_X509_ACERT_free(x509);
        x509 = NULL;
    }

#endif
    return EXPECT_RESULT();
}

/* Test ACERT support, but with ASN functions only.
 *
 * This example acert_ietf has both Holder IssuerSerial
 * and Holder entityName fields.
 * */
int test_wolfSSL_X509_ACERT_asn(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_ACERT) && !defined(NO_CERTS)
    const byte     acert_ietf[] = \
    "-----BEGIN ATTRIBUTE CERTIFICATE-----\n"
    "MIICPTCCASUCAQEwN6AWMBGkDzANMQswCQYDVQQDDAJDQQIBAqEdpBswGTEXMBUG\n"
    "A1UEAwwOc2VydmVyLmV4YW1wbGWgLTArpCkwJzElMCMGA1UEAwwcQXR0cmlidXRl\n"
    "IENlcnRpZmljYXRlIElzc3VlcjANBgkqhkiG9w0BAQsFAAIUA7WQWQKiqrVAIUS4\n"
    "LE/ZgBtfV8IwIhgPMjAyMTA2MTUxMjM1MDBaGA8yMDMxMDYxMzEyMzUwMFowQTAj\n"
    "BggrBgEFBQcKBDEXMBWgCYYHVGVzdHZhbDAIDAZncm91cDEwGgYDVQRIMRMwEaEP\n"
    "gw1hZG1pbmlzdHJhdG9yMCwwHwYDVR0jBBgwFoAUYm7JaGdsZLtTgt0tqoCK2MrI\n"
    "i10wCQYDVR04BAIFADANBgkqhkiG9w0BAQsFAAOCAQEAlIOJ2Dj3TEUj6BIv6vUs\n"
    "GqFWms05i+d10XSzWrunlUTQPoJcUjYkifOWp/7RpZ2XnRl+6hH+nIbmwSmXWwBn\n"
    "ERw2bQMmw/""/nWuN4Qv9t7ltuovWC0pJX6VMT1IRTuTV4SxuZpFL37vkmnFlPBlb+\n"
    "mn3ESSxLTjThWFIq1tip4IaxE/i5Uh32GlJglatFHM1PCGoJtyLtYb6KHDlvknw6\n"
    "coDyjIcj0FZwtQw41jLwxI8jWNmrpt978wdpprB/URrRs+m02HmeQoiHFi/qvdv8\n"
    "d+5vHf3Pi/ulhz/+dvr0p1vEQSoFnYxLXuty2p5m3PJPZCFmT3gURgmgR3BN9d7A\n"
    "Bw==\n"
    "-----END ATTRIBUTE CERTIFICATE-----\n";
    int            rc = 0;
    int            n_diff = 0;
    byte           ietf_serial[] =      {0x03, 0xb5, 0x90, 0x59, 0x02,
                                         0xa2, 0xaa, 0xb5, 0x40, 0x21,
                                         0x44, 0xb8, 0x2c, 0x4f, 0xd9,
                                         0x80, 0x1b, 0x5f, 0x57, 0xc2};
    byte           holderIssuerName[] = {0x31, 0x0b, 0x30, 0x09, 0x06,
                                         0x03, 0x55, 0x04, 0x03, 0x0c,
                                         0x02, 0x43, 0x41};
    byte           holderEntityName[] = {0x31, 0x17, 0x30, 0x15, 0x06,
                                         0x03, 0x55, 0x04, 0x03, 0x0c,
                                         0x0e, 0x73, 0x65, 0x72, 0x76,
                                         0x65, 0x72, 0x2e, 0x65, 0x78,
                                         0x61, 0x6d, 0x70, 0x6c, 0x65};
    DerBuffer *    der = NULL;
    WC_DECLARE_VAR(acert, DecodedAcert, 1, 0);

    rc = wc_PemToDer(acert_ietf, sizeof(acert_ietf), ACERT_TYPE, &der,
                     HEAP_HINT, NULL, NULL);

    ExpectIntEQ(rc, 0);
    ExpectNotNull(der);

    if (der != NULL) {
        ExpectNotNull(der->buffer);
    }

#ifdef WOLFSSL_SMALL_STACK
    acert = (DecodedAcert*)XMALLOC(sizeof(DecodedAcert), HEAP_HINT,
                                   DYNAMIC_TYPE_DCERT);
    ExpectNotNull(acert);
#else
    XMEMSET(acert, 0, sizeof(DecodedAcert));
#endif

    if (der != NULL && der->buffer != NULL
#ifdef WOLFSSL_SMALL_STACK
        && acert != NULL
#endif
    ) {
        wc_InitDecodedAcert(acert, der->buffer, der->length, HEAP_HINT);
        rc = wc_ParseX509Acert(acert, VERIFY_SKIP_DATE);
        ExpectIntEQ(rc, 0);

        ExpectIntEQ(acert->serialSz, 20);
        ExpectIntEQ(XMEMCMP(acert->serial, ietf_serial, sizeof(ietf_serial)),
                    0);

        /* This cert has a 65 byte attributes field. */
        ExpectNotNull(acert->rawAttr);
        ExpectIntEQ(acert->rawAttrLen, 65);

        ExpectNotNull(acert->holderIssuerName);
        ExpectNotNull(acert->holderEntityName);

        if ((acert->holderIssuerName != NULL) &&
            (acert->holderEntityName != NULL)) {
            ExpectNotNull(acert->holderEntityName->name);
            ExpectNotNull(acert->holderIssuerName->name);
        }
        if ((acert->holderIssuerName != NULL) &&
            (acert->holderEntityName != NULL) &&
            (acert->holderIssuerName->name != NULL) &&
            (acert->holderEntityName->name != NULL)) {
            ExpectIntEQ(acert->holderIssuerName->len,
                        sizeof(holderIssuerName));
            ExpectIntEQ(acert->holderEntityName->len,
                        sizeof(holderEntityName));

            ExpectIntEQ(acert->holderIssuerName->type, ASN_DIR_TYPE);
            ExpectIntEQ(acert->holderEntityName->type, ASN_DIR_TYPE);

            n_diff = XMEMCMP(acert->holderIssuerName->name, holderIssuerName,
                             sizeof(holderIssuerName));
            ExpectIntEQ(n_diff, 0);

            n_diff = XMEMCMP(acert->holderEntityName->name, holderEntityName,
                             sizeof(holderEntityName));
            ExpectIntEQ(n_diff, 0);
        }

        wc_FreeDecodedAcert(acert);
    }

#ifdef WOLFSSL_SMALL_STACK
    if (acert != NULL) {
        XFREE(acert, HEAP_HINT, DYNAMIC_TYPE_DCERT);
        acert = NULL;
    }
#endif

    if (der != NULL) {
        wc_FreeDer(&der);
        der = NULL;
    }

#endif
    return EXPECT_RESULT();
}


