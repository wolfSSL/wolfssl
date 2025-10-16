/* test_tls_ext.c
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

#include <wolfssl/internal.h>
#include <tests/utils.h>
#include <tests/api/test_tls_ext.h>

int test_tls_ems_downgrade(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_TLS12) && \
        defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
        defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL;
    WOLFSSL_CTX *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL;
    WOLFSSL *ssl_s = NULL;
    WOLFSSL_SESSION* session = NULL;
    /* TLS EMS extension in binary form */
    const char ems_ext[] = { 0x00, 0x17, 0x00, 0x00 };
    char data = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLS_client_method, wolfTLS_server_method), 0);

    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Verify that the EMS extension is present in Client's message */
    ExpectNotNull(mymemmem(test_ctx.s_buff, test_ctx.s_len,
            ems_ext, sizeof(ems_ext)));

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_version(ssl_c), TLS1_3_VERSION);

    /* Do a round of reads to exchange the ticket message */
    ExpectIntEQ(wolfSSL_read(ssl_s, &data, sizeof(data)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
    ExpectIntEQ(wolfSSL_read(ssl_c, &data, sizeof(data)), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    ExpectNotNull(session = wolfSSL_get1_session(ssl_c));
    ExpectTrue(session->haveEMS);

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLS_client_method, wolfTLS_server_method), 0);

    /* Resuming the connection */
    ExpectIntEQ(wolfSSL_set_session(ssl_c, session), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_connect(ssl_c), -1);
    ExpectIntEQ(wolfSSL_get_error(ssl_c, -1), WOLFSSL_ERROR_WANT_READ);

    /* Verify that the EMS extension is still present in the resumption CH
     * even though we used TLS 1.3 */
    ExpectNotNull(mymemmem(test_ctx.s_buff, test_ctx.s_len,
            ems_ext, sizeof(ems_ext)));

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_version(ssl_c), TLS1_3_VERSION);

    wolfSSL_SESSION_free(session);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}


int test_wolfSSL_DisableExtendedMasterSecret(void)
{
    EXPECT_DECLS;
#if defined(HAVE_EXTENDED_MASTER) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS)
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    WOLFSSL     *ssl = wolfSSL_new(ctx);

    ExpectNotNull(ctx);
    ExpectNotNull(ssl);

    /* error cases */
    ExpectIntNE(WOLFSSL_SUCCESS, wolfSSL_CTX_DisableExtendedMasterSecret(NULL));
    ExpectIntNE(WOLFSSL_SUCCESS, wolfSSL_DisableExtendedMasterSecret(NULL));

    /* success cases */
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_CTX_DisableExtendedMasterSecret(ctx));
    ExpectIntEQ(WOLFSSL_SUCCESS, wolfSSL_DisableExtendedMasterSecret(ssl));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}


#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_CA_NAMES) && !defined(NO_BIO) && \
    !defined(NO_CERTS) && !defined(NO_TLS) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)) && (defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)) && \
    (defined(WOLFSSL_TLS13) || !defined(WOLFSSL_NO_TLS12)) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
struct client_cb_arg {
    WOLF_STACK_OF(X509_NAME) *names1;
    WOLF_STACK_OF(X509_NAME) *names2;
};

static int certificate_authorities_client_cb(WOLFSSL *ssl, void *_arg) {
    struct client_cb_arg *arg = (struct client_cb_arg *)_arg;
    arg->names1 = wolfSSL_get_client_CA_list(ssl);
    arg->names2 = wolfSSL_get0_peer_CA_list(ssl);

    if (!wolfSSL_use_certificate_file(ssl, cliCertFile, SSL_FILETYPE_PEM))
        return 0;
    if (!wolfSSL_use_PrivateKey_file(ssl, cliKeyFile, SSL_FILETYPE_PEM))
        return 0;
    return 1;
}
#endif

int test_certificate_authorities_certificate_request(void) {
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_CA_NAMES) && !defined(NO_BIO) && \
    !defined(NO_CERTS) && !defined(NO_TLS) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)) && (defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)) && \
    (defined(WOLFSSL_TLS13) || !defined(WOLFSSL_NO_TLS12)) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    struct test_params {
        method_provider client_meth;
        method_provider server_meth;
        int             doUdp;
    } params[] = {
#ifdef WOLFSSL_TLS13
        /* TLS 1.3 uses certificate_authorities extension */
        {wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, 0},
#endif
#if !defined(WOLFSSL_NO_TLS12) && (defined(OPENSSL_ALL) || \
            defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY))
        /* TLS 1.2 directly embeds CA names in CertificateRequest */
        {wolfTLSv1_2_client_method, wolfTLSv1_2_server_method, 0},
#endif
#ifdef WOLFSSL_DTLS13
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, 1},
#endif
#if defined(WOLFSSL_DTLS) && (defined(OPENSSL_ALL) || \
            defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY))
        {wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method, 1},
#endif
    };
    size_t i;

    for (i = 0; i < sizeof(params) / sizeof(*params); i++) {
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX *ctx_srv = NULL;
        WOLFSSL *ssl_srv = NULL;
        WOLFSSL_CTX *ctx_cli = NULL;
        WOLFSSL *ssl_cli = NULL;
        WOLF_STACK_OF(X509_NAME) *names1 = NULL, *names2 = NULL;
        X509_NAME *name = NULL;
        struct client_cb_arg cb_arg = { NULL, NULL };
        const char *expected_names[] = {
            "/C=US/ST=Montana/L=Bozeman/O=wolfSSL_2048/OU=Programming-2048"
                "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com",
            "/C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting"
                "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
        };

        if (EXPECT_FAIL())
            break;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(0, test_memio_setup(&test_ctx, &ctx_cli, &ctx_srv,
                    &ssl_cli, NULL, params[i].client_meth,
                    params[i].server_meth));

        wolfSSL_CTX_set_verify(ctx_srv,
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        ExpectIntEQ(WOLFSSL_SUCCESS,
                wolfSSL_CTX_load_verify_locations(ctx_srv, cliCertFile, NULL));

        ExpectNotNull(ssl_srv = wolfSSL_new(ctx_srv));
        wolfSSL_SetIOReadCtx(ssl_srv, &test_ctx);
        wolfSSL_SetIOWriteCtx(ssl_srv, &test_ctx);

        names1 = wolfSSL_load_client_CA_file(cliCertFile);
        ExpectNotNull(names1);
        names2 = wolfSSL_load_client_CA_file(caCertFile);
        ExpectNotNull(names2);
        ExpectNotNull(name = wolfSSL_sk_X509_NAME_value(names2, 0));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_push(names1, name));
        if (EXPECT_FAIL()) {
            wolfSSL_X509_NAME_free(name);
            name = NULL;
        }
        wolfSSL_sk_X509_NAME_free(names2);
        names2 = wolfSSL_load_client_CA_file(caCertFile);
        ExpectNotNull(names2);

        /* Check that client_CA_list and CA_list are separate internally */
        wolfSSL_CTX_set_client_CA_list(ctx_srv, names1);
        wolfSSL_CTX_set0_CA_list(ctx_srv, names2);
        ExpectNotNull(names1 = wolfSSL_CTX_get_client_CA_list(ctx_srv));
        ExpectNotNull(names2 = wolfSSL_CTX_get0_CA_list(ctx_srv));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_num(names1));
        ExpectIntEQ(1, wolfSSL_sk_X509_NAME_num(names2));

        /* Check that get_client_CA_list and get0_CA_list on ssl return same as
         * ctx when not set */
        ExpectNotNull(names1 = wolfSSL_get_client_CA_list(ssl_srv));
        ExpectNotNull(names2 = wolfSSL_get0_CA_list(ssl_srv));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_num(names1));
        ExpectIntEQ(1, wolfSSL_sk_X509_NAME_num(names2));

        /* Same checks as before, but on ssl rather than ctx */
        names1 = wolfSSL_load_client_CA_file(cliCertFile);
        ExpectNotNull(names1);
        names2 = wolfSSL_load_client_CA_file(caCertFile);
        ExpectNotNull(names2);
        ExpectNotNull(name = wolfSSL_sk_X509_NAME_value(names2, 0));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_push(names1, name));
        if (EXPECT_FAIL()) {
            wolfSSL_X509_NAME_free(name);
            name = NULL;
        }
        wolfSSL_sk_X509_NAME_free(names2);
        names2 = wolfSSL_load_client_CA_file(caCertFile);
        ExpectNotNull(names2);

        wolfSSL_set_client_CA_list(ssl_srv, names1);
        wolfSSL_set0_CA_list(ssl_srv, names2);
        ExpectNotNull(names1 = wolfSSL_get_client_CA_list(ssl_srv));
        ExpectNotNull(names2 = wolfSSL_get0_CA_list(ssl_srv));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_num(names1));
        ExpectIntEQ(1, wolfSSL_sk_X509_NAME_num(names2));

#if !defined(NO_DH)
        SetDH(ssl_srv);
#endif

        /* Certs will be loaded in callback */
        wolfSSL_CTX_set_cert_cb(ctx_cli,
                certificate_authorities_client_cb, &cb_arg);

        ExpectIntEQ(0, test_memio_do_handshake(ssl_cli, ssl_srv, 10, NULL));

        ExpectNotNull(cb_arg.names1);
        ExpectNotNull(cb_arg.names2);
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_num(cb_arg.names1));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_num(cb_arg.names2));

        if (EXPECT_SUCCESS()) {
            ExpectStrEQ(wolfSSL_sk_X509_NAME_value(cb_arg.names1, 0)->name,
                    expected_names[0]);
            ExpectStrEQ(wolfSSL_sk_X509_NAME_value(cb_arg.names1, 1)->name,
                    expected_names[1]);
        }

        wolfSSL_shutdown(ssl_cli);
        wolfSSL_free(ssl_cli);
        wolfSSL_CTX_free(ctx_cli);
        wolfSSL_free(ssl_srv);
        wolfSSL_CTX_free(ctx_srv);
    }
#endif
    return EXPECT_RESULT();
}


#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_CA_NAMES) && !defined(NO_BIO) && \
    !defined(NO_CERTS) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)) && (defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)) && \
    defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
static int certificate_authorities_server_cb(WOLFSSL *ssl, void *_arg) {
    WOLF_STACK_OF(X509_NAME) **names_out = (WOLF_STACK_OF(X509_NAME) **)_arg;
    WOLF_STACK_OF(X509_NAME) *names = wolfSSL_get0_peer_CA_list(ssl);
    *names_out = names;
    if (!wolfSSL_use_certificate_file(ssl, svrCertFile, SSL_FILETYPE_PEM))
        return 0;
    if (!wolfSSL_use_PrivateKey_file(ssl, svrKeyFile, SSL_FILETYPE_PEM))
        return 0;
    return 1;
}
#endif

int test_certificate_authorities_client_hello(void) {
    EXPECT_DECLS;
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_CA_NAMES) && !defined(NO_BIO) && \
    !defined(NO_CERTS) && (defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)) && (defined(OPENSSL_ALL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)) && \
    defined(WOLFSSL_TLS13) && defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)

    struct test_params {
        method_provider client_meth;
        method_provider server_meth;
        int             doUdp;
    } params[] = {
    /* TLS >= 1.3 only */
#ifdef WOLFSSL_TLS13
        {wolfTLSv1_3_client_method, wolfTLSv1_3_server_method, 0},
#endif
#ifdef WOLFSSL_DTLS13
        {wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method, 1},
#endif
    };
    size_t i;

    for (i = 0; i < sizeof(params) / sizeof(*params); i++) {
        struct test_memio_ctx test_ctx;
        WOLFSSL_CTX *ctx_srv = NULL;
        WOLFSSL *ssl_srv = NULL;
        WOLFSSL_CTX *ctx_cli = NULL;
        WOLFSSL *ssl_cli = NULL;
        WOLF_STACK_OF(X509_NAME) *cb_arg = NULL;
        WOLF_STACK_OF(X509_NAME) *names1 = NULL, *names2 = NULL;
        X509_NAME *name = NULL;
        const char *expected_names[] = {
            "/C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting"
                "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com",
            "/C=US/ST=Montana/L=Bozeman/O=wolfSSL_2048/OU=Programming-2048"
                "/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
        };

        if (EXPECT_FAIL())
            break;

        XMEMSET(&test_ctx, 0, sizeof(test_ctx));

        ExpectIntEQ(0, test_memio_setup(&test_ctx, &ctx_cli, &ctx_srv,
                    &ssl_cli, &ssl_srv, params[i].client_meth,
                    params[i].server_meth));

        wolfSSL_CTX_set_cert_cb(ctx_srv, certificate_authorities_server_cb,
                &cb_arg);

        names1 = wolfSSL_load_client_CA_file(caCertFile);
        ExpectNotNull(names1);
        names2 = wolfSSL_load_client_CA_file(cliCertFile);
        ExpectNotNull(names2);
        ExpectNotNull(name = wolfSSL_sk_X509_NAME_value(names2, 0));
        ExpectIntEQ(2, wolfSSL_sk_X509_NAME_push(names1, name));
        if (EXPECT_FAIL()) {
            wolfSSL_X509_NAME_free(name);
            name = NULL;
        }
        wolfSSL_sk_X509_NAME_free(names2);
        names2 = wolfSSL_load_client_CA_file(cliCertFile);
        ExpectNotNull(names2);

        /* verify that set0_CA_list takes precedence */
        wolfSSL_set0_CA_list(ssl_cli, names1);
        wolfSSL_CTX_set0_CA_list(ctx_cli, names2);

        ExpectIntEQ(0, test_memio_do_handshake(ssl_cli, ssl_srv, 10, NULL));

        ExpectIntEQ(wolfSSL_sk_X509_NAME_num(cb_arg), 2);

        if (EXPECT_SUCCESS()) {
            ExpectStrEQ(wolfSSL_sk_X509_NAME_value(cb_arg, 0)->name,
                    expected_names[0]);
            ExpectStrEQ(wolfSSL_sk_X509_NAME_value(cb_arg, 1)->name,
                    expected_names[1]);
        }

        wolfSSL_shutdown(ssl_cli);
        wolfSSL_free(ssl_cli);
        wolfSSL_CTX_free(ctx_cli);
        wolfSSL_free(ssl_srv);
        wolfSSL_CTX_free(ctx_srv);
    }
#endif
    return EXPECT_RESULT();
}
