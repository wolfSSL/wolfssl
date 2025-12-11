/* test_ossl_x509_lu.c
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
#include <tests/api/test_ossl_x509_lu.h>

int test_wolfSSL_X509_LOOKUP_load_file(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && \
   !defined(NO_FILESYSTEM) && !defined(NO_RSA) && defined(HAVE_ECC) && \
   (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH))
    WOLFSSL_X509_STORE*  store = NULL;
    WOLFSSL_X509_LOOKUP* lookup = NULL;

    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectNotNull(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()));
    /* One RSA and one ECC certificate in file. */
    ExpectIntEQ(wolfSSL_X509_LOOKUP_load_file(lookup, "certs/client-ca.pem",
        X509_FILETYPE_PEM), 1);
    ExpectIntEQ(wolfSSL_X509_LOOKUP_load_file(lookup, "certs/crl/crl2.pem",
        X509_FILETYPE_PEM), 1);

    if (store != NULL) {
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm, cliCertFile,
            WOLFSSL_FILETYPE_PEM), 1);
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm, svrCertFile,
            WOLFSSL_FILETYPE_PEM), WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));
    }
    ExpectIntEQ(wolfSSL_X509_LOOKUP_load_file(lookup, "certs/ca-cert.pem",
        X509_FILETYPE_PEM), 1);
    if (store != NULL) {
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm, svrCertFile,
            WOLFSSL_FILETYPE_PEM), 1);
    }

    wolfSSL_X509_STORE_free(store);
#endif /* defined(OPENSSL_EXTRA) && defined(HAVE_CRL) &&
        * !defined(NO_FILESYSTEM) && !defined(NO_RSA) */
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_LOOKUP_ctrl_file(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_CERTS) && \
    !defined(NO_FILESYSTEM) && !defined(NO_RSA) && \
    defined(WOLFSSL_SIGNER_DER_CERT)
    X509_STORE_CTX* ctx = NULL;
    X509_STORE* str = NULL;
    X509_LOOKUP* lookup = NULL;

    X509* cert1 = NULL;
    X509* x509Ca = NULL;
    X509* x509Svr = NULL;
    X509* issuer = NULL;

    WOLFSSL_STACK* sk = NULL;
    X509_NAME* caName = NULL;
    X509_NAME* issuerName = NULL;

    XFILE file1 = XBADFILE;
    int i;
    int cert_count = 0;
    int cmp;

    char der[] = "certs/ca-cert.der";

#ifdef HAVE_CRL
    char pem[][100] = {
        "./certs/crl/crl.pem",
        "./certs/crl/crl2.pem",
        "./certs/crl/caEccCrl.pem",
        "./certs/crl/eccCliCRL.pem",
        "./certs/crl/eccSrvCRL.pem",
        ""
    };
#endif
    ExpectTrue((file1 = XFOPEN("./certs/ca-cert.pem", "rb")) != XBADFILE);
    ExpectNotNull(cert1 = wolfSSL_PEM_read_X509(file1, NULL, NULL, NULL));
    if (file1 != XBADFILE)
        XFCLOSE(file1);

    ExpectNotNull(ctx = X509_STORE_CTX_new());
    ExpectNotNull((str = wolfSSL_X509_STORE_new()));
    ExpectNotNull(lookup = X509_STORE_add_lookup(str, X509_LOOKUP_file()));
    ExpectIntEQ(wolfSSL_X509_load_cert_crl_file(NULL, NULL,
        WOLFSSL_FILETYPE_PEM), 0);
    ExpectIntEQ(wolfSSL_X509_load_cert_crl_file(lookup, NULL,
        WOLFSSL_FILETYPE_PEM), 0);
    ExpectIntEQ(wolfSSL_X509_load_cert_crl_file(NULL, caCertFile,
        WOLFSSL_FILETYPE_PEM), 0);
    ExpectIntEQ(wolfSSL_X509_load_cert_crl_file(NULL, der       ,
        WOLFSSL_FILETYPE_PEM), 0);
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, caCertFile,
                                    SSL_FILETYPE_PEM,NULL), 1);
    ExpectNotNull(sk = wolfSSL_CertManagerGetCerts(str->cm));
    ExpectIntEQ((cert_count = sk_X509_num(sk)), 1);

    /* check if CA cert is loaded into the store */
    for (i = 0; i < cert_count; i++) {
        x509Ca = sk_X509_value(sk, i);
        ExpectIntEQ(0, wolfSSL_X509_cmp(x509Ca, cert1));
    }

    ExpectNotNull((x509Svr =
            wolfSSL_X509_load_certificate_file(svrCertFile, SSL_FILETYPE_PEM)));

    ExpectIntEQ(X509_STORE_CTX_init(ctx, str, x509Svr, NULL), SSL_SUCCESS);

    ExpectNull(X509_STORE_CTX_get0_current_issuer(NULL));
    issuer = X509_STORE_CTX_get0_current_issuer(ctx);
    ExpectNull(issuer);

    ExpectIntEQ(X509_verify_cert(ctx), 1);

    issuer = X509_STORE_CTX_get0_current_issuer(ctx);
    ExpectNotNull(issuer);
    caName = X509_get_subject_name(x509Ca);
    ExpectNotNull(caName);
    issuerName = X509_get_subject_name(issuer);
    ExpectNotNull(issuerName);
    cmp = X509_NAME_cmp(caName, issuerName);
    ExpectIntEQ(cmp, 0);
    /* load der format */
    issuer = NULL;
    X509_STORE_CTX_free(ctx);
    ctx = NULL;
    X509_STORE_free(str);
    str = NULL;
    sk_X509_pop_free(sk, NULL);
    sk = NULL;
    X509_free(x509Svr);
    x509Svr = NULL;

    ExpectNotNull((str = wolfSSL_X509_STORE_new()));
    ExpectNotNull(lookup = X509_STORE_add_lookup(str, X509_LOOKUP_file()));
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, der,
                                    SSL_FILETYPE_ASN1,NULL), 1);
    ExpectNotNull(sk = wolfSSL_CertManagerGetCerts(str->cm));
    ExpectIntEQ((cert_count = sk_X509_num(sk)), 1);
    /* check if CA cert is loaded into the store */
    for (i = 0; i < cert_count; i++) {
        x509Ca = sk_X509_value(sk, i);
        ExpectIntEQ(0, wolfSSL_X509_cmp(x509Ca, cert1));
    }

    X509_STORE_free(str);
    str = NULL;
    sk_X509_pop_free(sk, NULL);
    sk = NULL;
    X509_free(cert1);
    cert1 = NULL;

#ifdef HAVE_CRL
    ExpectNotNull(str = wolfSSL_X509_STORE_new());
    ExpectNotNull(lookup = X509_STORE_add_lookup(str, X509_LOOKUP_file()));
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, caCertFile,
                                                    SSL_FILETYPE_PEM,NULL), 1);
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD,
                                "certs/server-revoked-cert.pem",
                                 SSL_FILETYPE_PEM,NULL), 1);
    if (str) {
        ExpectIntEQ(wolfSSL_CertManagerVerify(str->cm, svrCertFile,
                    WOLFSSL_FILETYPE_PEM), 1);
        /* since store hasn't yet known the revoked cert*/
        ExpectIntEQ(wolfSSL_CertManagerVerify(str->cm,
                    "certs/server-revoked-cert.pem",
                    WOLFSSL_FILETYPE_PEM), 1);
    }
    for (i = 0; pem[i][0] != '\0'; i++)
    {
        ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, pem[i],
                                        SSL_FILETYPE_PEM, NULL), 1);
    }

    if (str) {
        /* since store knows crl list */
        ExpectIntEQ(wolfSSL_CertManagerVerify(str->cm,
                    "certs/server-revoked-cert.pem",
                    WOLFSSL_FILETYPE_PEM ), WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
    }

    ExpectIntEQ(X509_LOOKUP_ctrl(NULL, 0, NULL, 0, NULL), 0);
    X509_STORE_free(str);
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_LOOKUP_ctrl_hash_dir(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
    const int  MAX_DIR = 4;
    const char paths[][32] = {
                             "./certs/ed25519",
                             "./certs/ecc",
                             "./certs/crl",
                             "./certs/",
                            };

    char CertCrl_path[MAX_FILENAME_SZ];
    char *p;
    X509_STORE* str = NULL;
    X509_LOOKUP* lookup = NULL;
    WOLFSSL_STACK* sk = NULL;
    int len, total_len, i;

    (void)sk;

    XMEMSET(CertCrl_path, 0, MAX_FILENAME_SZ);

    /* illegal string */
    ExpectNotNull((str = wolfSSL_X509_STORE_new()));
    ExpectNotNull(lookup = X509_STORE_add_lookup(str, X509_LOOKUP_file()));
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_ADD_DIR, "",
                                    SSL_FILETYPE_PEM, NULL), 0);
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_ADD_STORE, "",
        SSL_FILETYPE_PEM, NULL), WOLFSSL_NOT_IMPLEMENTED);
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_LOAD_STORE, "",
        SSL_FILETYPE_PEM, NULL), WOLFSSL_NOT_IMPLEMENTED);
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, 0, "",
        SSL_FILETYPE_PEM, NULL), WOLFSSL_FAILURE);

    /* free store */
    X509_STORE_free(str);
    str = NULL;

    /* short folder string */
    ExpectNotNull((str = wolfSSL_X509_STORE_new()));
    ExpectNotNull(lookup = X509_STORE_add_lookup(str, X509_LOOKUP_file()));
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_ADD_DIR, "./",
                                    SSL_FILETYPE_PEM,NULL), 1);
    #if defined(WOLFSSL_INT_H)
    /* only available when including internal.h */
    ExpectNotNull(sk = lookup->dirs->dir_entry);
    #endif
    /* free store */
    X509_STORE_free(str);
    str = NULL;

    /* typical function check */
    p = &CertCrl_path[0];
    total_len = 0;

    for (i = MAX_DIR - 1; i>=0 && total_len < MAX_FILENAME_SZ; i--) {
        len = (int)XSTRLEN((const char*)&paths[i]);
        total_len += len;
        XSTRNCPY(p, paths[i], MAX_FILENAME_SZ - total_len);
        p += len;
        if (i != 0) *(p++) = SEPARATOR_CHAR;
    }

    ExpectNotNull((str = wolfSSL_X509_STORE_new()));
    ExpectNotNull(lookup = X509_STORE_add_lookup(str, X509_LOOKUP_file()));
    ExpectIntEQ(X509_LOOKUP_ctrl(lookup, X509_L_ADD_DIR, CertCrl_path,
                                    SSL_FILETYPE_PEM,NULL), 1);
    #if defined(WOLFSSL_INT_H)
    /* only available when including internal.h */
    ExpectNotNull(sk = lookup->dirs->dir_entry);
    #endif

    X509_STORE_free(str);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_load_crl_file(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM) && !defined(NO_RSA) && !defined(NO_BIO) && \
    !defined(WOLFSSL_CRL_ALLOW_MISSING_CDP)
    int i;
    char pem[][100] = {
        "./certs/crl/crl.pem",
        "./certs/crl/crl2.pem",
        "./certs/crl/caEccCrl.pem",
        "./certs/crl/eccCliCRL.pem",
        "./certs/crl/eccSrvCRL.pem",
    #ifdef WC_RSA_PSS
        "./certs/crl/crl_rsapss.pem",
    #endif
        ""
    };
    char der[][100] = {
        "./certs/crl/crl.der",
        "./certs/crl/crl2.der",
        ""
    };
    WOLFSSL_X509_STORE*  store = NULL;
    WOLFSSL_X509_LOOKUP* lookup = NULL;

    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectNotNull(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()));

    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/ca-cert.pem",
        X509_FILETYPE_PEM), 1);
#ifdef WC_RSA_PSS
    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/rsapss/ca-rsapss.pem",
        X509_FILETYPE_PEM), 1);
#endif
    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/server-revoked-cert.pem",
        X509_FILETYPE_PEM), 1);
    if (store) {
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm, svrCertFile,
            WOLFSSL_FILETYPE_PEM), 1);
        /* since store hasn't yet known the revoked cert*/
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm,
            "certs/server-revoked-cert.pem", WOLFSSL_FILETYPE_PEM), 1);
    }

    ExpectIntEQ(X509_load_crl_file(lookup, pem[0], 0), 0);
    for (i = 0; pem[i][0] != '\0'; i++) {
        ExpectIntEQ(X509_load_crl_file(lookup, pem[i], WOLFSSL_FILETYPE_PEM),
            1);
    }

    if (store) {
        /* since store knows crl list */
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm,
            "certs/server-revoked-cert.pem", WOLFSSL_FILETYPE_PEM),
            WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
#ifdef WC_RSA_PSS
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm,
            "certs/rsapss/server-rsapss-cert.pem", WOLFSSL_FILETYPE_PEM),
            WC_NO_ERR_TRACE(ASN_NO_SIGNER_E));
#endif
    }
    /* once feeing store */
    X509_STORE_free(store);
    store = NULL;

    ExpectNotNull(store = wolfSSL_X509_STORE_new());
    ExpectNotNull(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()));

    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/ca-cert.pem",
        X509_FILETYPE_PEM), 1);
    ExpectIntEQ(X509_LOOKUP_load_file(lookup, "certs/server-revoked-cert.pem",
        X509_FILETYPE_PEM), 1);
    if (store) {
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm, svrCertFile,
            WOLFSSL_FILETYPE_PEM), 1);
        /* since store hasn't yet known the revoked cert*/
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm,
            "certs/server-revoked-cert.pem", WOLFSSL_FILETYPE_PEM), 1);
    }

    for (i = 0; der[i][0] != '\0'; i++) {
        ExpectIntEQ(X509_load_crl_file(lookup, der[i], WOLFSSL_FILETYPE_ASN1),
            1);
    }

    if (store) {
        /* since store knows crl list */
        ExpectIntEQ(wolfSSL_CertManagerVerify(store->cm,
            "certs/server-revoked-cert.pem", WOLFSSL_FILETYPE_PEM),
            WC_NO_ERR_TRACE(CRL_CERT_REVOKED));
    }

    /* test for incorrect parameter */
    ExpectIntEQ(X509_load_crl_file(NULL, pem[0], 0), 0);
    ExpectIntEQ(X509_load_crl_file(lookup, NULL, 0), 0);
    ExpectIntEQ(X509_load_crl_file(NULL, NULL, 0), 0);

    X509_STORE_free(store);
    store = NULL;
#endif
    return EXPECT_RESULT();
}

int test_X509_LOOKUP_add_dir(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN) && \
    (defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_EXT)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)  && \
    (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)) && \
    defined(HAVE_CRL) && !defined(NO_RSA)

    X509_STORE *     store = NULL;
    X509_STORE_CTX * storeCtx = NULL;
    X509_CRL *       crl = NULL;
    X509 *           ca = NULL;
    X509 *           cert = NULL;
    const char       cliCrlPem[] = "./certs/crl/cliCrl.pem";
    const char       srvCert[] = "./certs/server-cert.pem";
    const char       caCert[] = "./certs/ca-cert.pem";
    const char       caDir[] = "./certs/crl/hash_der";
    XFILE            fp = XBADFILE;
    X509_LOOKUP *    lookup = NULL;

    ExpectNotNull(store = (X509_STORE *)X509_STORE_new());

    /* Set up store with CA */
    ExpectNotNull((ca = wolfSSL_X509_load_certificate_file(caCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);

    /* Add CRL lookup directory to store.
     * Test uses ./certs/crl/hash_der/0fdb2da4.r0, which is a copy
     * of crl.der */
    ExpectNotNull((lookup = X509_STORE_add_lookup(store,
        X509_LOOKUP_hash_dir())));

    ExpectIntEQ(X509_LOOKUP_add_dir(lookup, caDir, X509_FILETYPE_ASN1),
        SSL_SUCCESS);

    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        SSL_SUCCESS);

    /* Add CRL to store NOT containing the verified certificate, which
     * forces use of the CRL lookup directory */
    ExpectTrue((fp = XFOPEN(cliCrlPem, "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL *)PEM_read_X509_CRL(fp, (X509_CRL **)NULL,
        NULL, NULL));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    ExpectIntEQ(X509_STORE_add_crl(store, crl), SSL_SUCCESS);

    /* Create verification context outside of an SSL session */
    ExpectNotNull((storeCtx = X509_STORE_CTX_new()));
    ExpectNotNull((cert = wolfSSL_X509_load_certificate_file(srvCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);

    /* Perform verification, which should NOT return CRL missing */
    ExpectIntNE(X509_verify_cert(storeCtx), WC_NO_ERR_TRACE(CRL_MISSING));

    X509_CRL_free(crl);
    crl = NULL;
    X509_STORE_free(store);
    store = NULL;
    X509_STORE_CTX_free(storeCtx);
    storeCtx = NULL;
    X509_free(cert);
    cert = NULL;
    X509_free(ca);
    ca = NULL;

    /* Now repeat the same, but look for X509_FILETYPE_PEM.
     * We should get CRL_MISSING at the end, because the lookup
     * dir has only ASN1 CRLs. */

    ExpectNotNull(store = (X509_STORE *)X509_STORE_new());

    ExpectNotNull((ca = wolfSSL_X509_load_certificate_file(caCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_add_cert(store, ca), SSL_SUCCESS);

    ExpectNotNull((lookup = X509_STORE_add_lookup(store,
        X509_LOOKUP_hash_dir())));

    ExpectIntEQ(X509_LOOKUP_add_dir(lookup, caDir, X509_FILETYPE_PEM),
        SSL_SUCCESS);

    ExpectIntEQ(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK),
        SSL_SUCCESS);
    ExpectTrue((fp = XFOPEN(cliCrlPem, "rb")) != XBADFILE);
    ExpectNotNull(crl = (X509_CRL *)PEM_read_X509_CRL(fp, (X509_CRL **)NULL,
        NULL, NULL));
    if (fp != XBADFILE) {
        XFCLOSE(fp);
        fp = XBADFILE;
    }
    ExpectIntEQ(X509_STORE_add_crl(store, crl), SSL_SUCCESS);

    ExpectNotNull((storeCtx = X509_STORE_CTX_new()));
    ExpectNotNull((cert = wolfSSL_X509_load_certificate_file(srvCert,
        SSL_FILETYPE_PEM)));
    ExpectIntEQ(X509_STORE_CTX_init(storeCtx, store, cert, NULL), SSL_SUCCESS);

    /* Now we SHOULD get CRL_MISSING, because we looked for PEM
     * in dir containing only ASN1/DER. */
    ExpectIntEQ(X509_verify_cert(storeCtx), WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
    ExpectIntEQ(X509_STORE_CTX_get_error(storeCtx),
            X509_V_ERR_UNABLE_TO_GET_CRL);

    X509_CRL_free(crl);
    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);
    X509_free(cert);
    X509_free(ca);
#endif
    return EXPECT_RESULT();
}

