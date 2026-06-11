/* test_ssl_ext.c
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

#include <tests/utils.h>
#include <tests/api/test_ssl_ext.h>

/* Tests for the TLS extension APIs in src/ssl_api_ext.c (moved from ssl.c).
 * These cover functions not already exercised elsewhere in api.c. */

int test_wolfSSL_NoTicketTLSv12_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER) && \
    (defined(NO_CERTS) || !defined(NO_RSA)) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* NULL arguments are rejected. */
    ExpectIntEQ(wolfSSL_CTX_NoTicketTLSv12(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    ExpectIntEQ(wolfSSL_CTX_NoTicketTLSv12(ctx), WOLFSSL_SUCCESS);
#ifndef NO_CERTS
    /* A server WOLFSSL needs a key and certificate set on the context. */
    ExpectIntEQ(wolfSSL_CTX_use_PrivateKey_file(ctx, svrKeyFile, CERT_FILETYPE),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_use_certificate_file(ctx, svrCertFile,
        CERT_FILETYPE), WOLFSSL_SUCCESS);
#endif
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_NoTicketTLSv12(ssl), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_UseMaxFragment_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MAX_FRAGMENT) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;

    /* NULL context is rejected. */
    ExpectIntEQ(wolfSSL_CTX_UseMaxFragment(NULL, WOLFSSL_MFL_2_9),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectIntEQ(wolfSSL_CTX_UseMaxFragment(ctx, WOLFSSL_MFL_2_9),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_UseMaxFragment(ctx, WOLFSSL_MFL_2_12),
        WOLFSSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_num_tickets_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_SERVER)
    WOLFSSL_CTX* ctx = NULL;

    /* NULL context: set fails, get returns zero. */
    ExpectIntEQ(wolfSSL_CTX_set_num_tickets(NULL, 5), WOLFSSL_FAILURE);
    ExpectIntEQ((int)wolfSSL_CTX_get_num_tickets(NULL), 0);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    ExpectIntEQ(wolfSSL_CTX_set_num_tickets(ctx, 3), WOLFSSL_SUCCESS);
    ExpectIntEQ((int)wolfSSL_CTX_get_num_tickets(ctx), 3);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_set1_groups_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int dummy[1];
#ifdef HAVE_ECC
    int groups[1];
#endif

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* A zero or too-large group count is rejected. */
    ExpectIntEQ(wolfSSL_CTX_set1_groups(ctx, dummy, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_CTX_set1_groups(ctx, dummy,
        WOLFSSL_MAX_GROUP_COUNT + 1), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set1_groups(ssl, dummy, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set1_groups(ssl, dummy,
        WOLFSSL_MAX_GROUP_COUNT + 1), WOLFSSL_FAILURE);

#ifdef HAVE_ECC
    /* A valid named group succeeds. */
    groups[0] = WOLFSSL_ECC_SECP256R1;
    ExpectIntEQ(wolfSSL_CTX_set1_groups(ctx, groups, 1), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set1_groups(ssl, groups, 1), WOLFSSL_SUCCESS);
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_set1_groups_list_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ECC) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_SUPPORTED_CURVES) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* NULL arguments are rejected. */
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(NULL, "P-256"), WOLFSSL_FAILURE);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(ctx, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set1_groups_list(ssl, NULL), WOLFSSL_FAILURE);

    /* A known group name succeeds. */
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(ctx, "P-256"), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set1_groups_list(ssl, "P-256"), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_set_TicketHint_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;

    ExpectIntEQ(wolfSSL_CTX_set_TicketHint(NULL, 100),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_server_method()));
    /* RFC 8446 caps the hint at 604800 seconds (7 days). */
    ExpectIntEQ(wolfSSL_CTX_set_TicketHint(ctx, -1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_set_TicketHint(ctx, 604801),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_set_TicketHint(ctx, 0), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set_TicketHint(ctx, 604800), WOLFSSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_tlsext_max_fragment_length_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_MAX_FRAGMENT) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(wolfSSL_CTX_set_tlsext_max_fragment_length(NULL,
        WOLFSSL_MFL_2_9), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* Modes outside the WOLFSSL_MFL_2_9..WOLFSSL_MFL_2_12 range are rejected. */
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_max_fragment_length(ctx,
        WOLFSSL_MFL_2_9 - 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_max_fragment_length(ctx,
        WOLFSSL_MFL_2_12 + 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_max_fragment_length(ctx,
        WOLFSSL_MFL_2_9), WOLFSSL_SUCCESS);

    ExpectIntEQ(wolfSSL_set_tlsext_max_fragment_length(NULL, WOLFSSL_MFL_2_9),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_set_tlsext_max_fragment_length(ssl, WOLFSSL_MFL_2_12),
        WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_DisableExtendedMasterSecret_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_EXTENDED_MASTER) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(wolfSSL_CTX_DisableExtendedMasterSecret(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_DisableExtendedMasterSecret(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectIntEQ(wolfSSL_CTX_DisableExtendedMasterSecret(ctx), WOLFSSL_SUCCESS);
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_DisableExtendedMasterSecret(ssl), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_set_tlsext_host_name_ext(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && defined(HAVE_SNI) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    ExpectIntEQ(wolfSSL_set_tlsext_host_name(ssl, "localhost"),
        WOLFSSL_SUCCESS);
#ifndef NO_WOLFSSL_SERVER
    /* On the client the host name just set is returned. */
    ExpectStrEQ(wolfSSL_get_servername(ssl, WOLFSSL_SNI_HOST_NAME),
        "localhost");
    ExpectNull(wolfSSL_get_servername(NULL, WOLFSSL_SNI_HOST_NAME));
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_set_tlsext_servername_callback_ext(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)) && defined(HAVE_SNI) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;

    ExpectIntEQ(wolfSSL_CTX_set_tlsext_servername_callback(NULL, NULL),
        WOLFSSL_FAILURE);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectIntEQ(wolfSSL_CTX_set_tlsext_servername_callback(ctx, NULL),
        WOLFSSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_set_tlsext_debug_arg_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_PK_CALLBACKS) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int arg = 0;

    ExpectIntEQ(wolfSSL_set_tlsext_debug_arg(NULL, &arg), WOLFSSL_FAILURE);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_tlsext_debug_arg(ssl, &arg), WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_set_SessionTicket_cb_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(wolfSSL_set_SessionTicket_cb(NULL, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_SessionTicket_cb(ssl, NULL, NULL),
        WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_set1_curves_list_ext(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_EXTRA) || defined(HAVE_CURL)) && \
    (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)) \
    && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* NULL object or list is rejected. */
    ExpectIntEQ(wolfSSL_set1_curves_list(NULL, "P-256"), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set1_curves_list(ssl, NULL), WOLFSSL_FAILURE);
#ifdef HAVE_ECC
    ExpectIntEQ(wolfSSL_set1_curves_list(ssl, "P-256"), WOLFSSL_SUCCESS);
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SecureResume_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SECURE_RENEGOTIATION) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectIntEQ(wolfSSL_SecureResume(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    /* Secure renegotiation has not been forced on, so resume is refused. */
    ExpectIntEQ(wolfSSL_SecureResume(ssl),
        WC_NO_ERR_TRACE(SECURE_RENEGOTIATION_E));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_UseSecureRenegotiation_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SERVER_RENEGOTIATION_INFO) && !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;

    /* NULL context is rejected. */
    ExpectIntEQ(wolfSSL_CTX_UseSecureRenegotiation(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectIntEQ(wolfSSL_CTX_UseSecureRenegotiation(ctx), WOLFSSL_SUCCESS);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_next_proto_cb_ext(void)
{
    EXPECT_DECLS;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) ||                         \
     defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY) ||                       \
     defined(WOLFSSL_QUIC)) && defined(HAVE_ALPN) &&                           \
     !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    const unsigned char* data = NULL;
    unsigned int len = 0;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* These NPN APIs are no-op stubs for OpenSSL compatibility. Exercise
     * them to confirm they accept NULL callbacks without crashing. */
    wolfSSL_CTX_set_next_protos_advertised_cb(ctx, NULL, NULL);
    wolfSSL_CTX_set_next_proto_select_cb(ctx, NULL, NULL);
    wolfSSL_get0_next_proto_negotiated(ssl, &data, &len);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_tlsext_status_exts_ids_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_STUB) &&                     \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* These status_request extension/id APIs are unimplemented stubs that
     * always report failure. */
    ExpectIntEQ(wolfSSL_get_tlsext_status_exts(ssl, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set_tlsext_status_exts(ssl, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_get_tlsext_status_ids(ssl, NULL), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set_tlsext_status_ids(ssl, NULL), WOLFSSL_FAILURE);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SNI_GetFromBuffer_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_SERVER) && !defined(NO_TLS)
    byte sni[32];
    word32 sniSz = (word32)sizeof(sni);
    byte hello[8] = { 0 };

    /* A NULL ClientHello buffer is rejected. */
    ExpectIntEQ(wolfSSL_SNI_GetFromBuffer(NULL, (word32)sizeof(hello), 0, sni,
        &sniSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_UseTrustedCA_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_TRUSTED_CA) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    const byte id[1] = { 0 };

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* The pre-agreed type must not carry an identifier. */
    ExpectIntEQ(wolfSSL_UseTrustedCA(ssl, WOLFSSL_TRUSTED_CA_PRE_AGREED, id, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_UseMaxFragment_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MAX_FRAGMENT) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS)
    /* A NULL object is rejected. */
    ExpectIntEQ(wolfSSL_UseMaxFragment(NULL, WOLFSSL_MFL_2_9),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_set1_groups_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SUPPORTED_CURVES) && defined(OPENSSL_EXTRA) &&                \
    defined(HAVE_ECC) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int badGroups[1];

    badGroups[0] = 0xFFFE; /* neither a named group nor a valid curve NID */

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* An unrecognized group identifier is rejected. */
    ExpectIntEQ(wolfSSL_set1_groups(ssl, badGroups, 1), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_CTX_set1_groups(ctx, badGroups, 1), WOLFSSL_FAILURE);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_UseALPN_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ALPN) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char proto[] = "h2";

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* A protocol-list length beyond the maximum is rejected. */
    ExpectIntEQ(wolfSSL_UseALPN(ssl, proto,
        (word32)(WOLFSSL_MAX_ALPN_NUMBER * WOLFSSL_MAX_ALPN_PROTO_NAME_LEN +
                 WOLFSSL_MAX_ALPN_NUMBER + 1),
        WOLFSSL_ALPN_CONTINUE_ON_MISMATCH), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* No mismatch option set is rejected. */
    ExpectIntEQ(wolfSSL_UseALPN(ssl, proto, (word32)XSTRLEN(proto), 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_ALPN_GetPeerProtocol_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ALPN) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char* list = NULL;
    word16 listSz = 0;

    /* NULL arguments are rejected. */
    ExpectIntEQ(wolfSSL_ALPN_GetPeerProtocol(NULL, &list, &listSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_ALPN_FreePeerProtocol(NULL, &list),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* The peer has not offered any protocols yet. */
    ExpectIntEQ(wolfSSL_ALPN_GetPeerProtocol(ssl, &list, &listSz),
        WC_NO_ERR_TRACE(BUFFER_ERROR));

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_set_TicketEncCb_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(NO_TLS)
    /* A NULL context is rejected. */
    ExpectIntEQ(wolfSSL_CTX_set_TicketEncCb(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_SessionTicket_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    byte tick[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    byte out[8];
    word32 outSz;
    byte big[4096];

    XMEMSET(big, 0x5a, sizeof(big));

    /* NULL object checks. */
    ExpectIntEQ(wolfSSL_UseSessionTicket(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_CTX_UseSessionTicket(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wolfSSL_set_SessionTicket(NULL, tick, (word32)sizeof(tick)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* set: a non-zero size with a NULL buffer is rejected. */
    ExpectIntEQ(wolfSSL_set_SessionTicket(ssl, NULL, 4),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* get: NULL object and NULL buffer with non-zero size are rejected. */
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wolfSSL_get_SessionTicket(NULL, out, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wolfSSL_get_SessionTicket(ssl, NULL, &outSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Store a short ticket (static-buffer path). */
    ExpectIntEQ(wolfSSL_set_SessionTicket(ssl, tick, (word32)sizeof(tick)),
        WOLFSSL_SUCCESS);
    /* Retrieving into a buffer that is too small reports zero length. */
    outSz = 2;
    ExpectIntEQ(wolfSSL_get_SessionTicket(ssl, out, &outSz), WOLFSSL_SUCCESS);
    ExpectIntEQ(outSz, 0);

    /* A ticket larger than the static buffer (SESSION_TICKET_LEN) uses
     * dynamic storage; growing it again frees the previous allocation, and a
     * later short ticket returns to the static buffer. */
    ExpectIntEQ(wolfSSL_set_SessionTicket(ssl, big, 3000), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_SessionTicket(ssl, big, 4000), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_SessionTicket(ssl, tick, (word32)sizeof(tick)),
        WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_set_servername_arg_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI)
    /* A NULL context is rejected. */
    ExpectIntEQ(wolfSSL_CTX_set_servername_arg(NULL, NULL), WOLFSSL_FAILURE);
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_CTX_set_alpn_protos_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    const unsigned char protos[] = { 2, 'h', '2' };
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    const int good = 0;
#else
    const int good = WOLFSSL_SUCCESS;
#endif

    /* A NULL context is rejected. */
    ExpectIntEQ(wolfSSL_CTX_set_alpn_protos(NULL, protos, (unsigned int)
        sizeof(protos)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    /* Setting twice exercises the free-previous-list path. */
    ExpectIntEQ(wolfSSL_CTX_set_alpn_protos(ctx, protos,
        (unsigned int)sizeof(protos)), good);
    ExpectIntEQ(wolfSSL_CTX_set_alpn_protos(ctx, protos,
        (unsigned int)sizeof(protos)), good);

    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}
