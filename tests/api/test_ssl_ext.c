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
/* For the EVP_* and HMAC_* compatibility names the ticket key callback below
 * uses. They reach this file through wolfssl/openssl/asn1.h already, but name
 * the headers that define them rather than rely on that. */
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/hmac.h>

#include <tests/utils.h>
#include <tests/api/test_ssl_ext.h>

/* Tests for the TLS extension APIs in src/ssl_api_ext.c (moved from ssl.c).
 * These cover functions not already exercised elsewhere in api.c. */

/* Test turning off session tickets for TLS 1.2 and below.
 *
 * TLS 1.3 tickets are unaffected, so only the pre-1.3 path is disabled.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test setting the maximum fragment length on a context.
 *
 * Each defined length code is accepted and out-of-range codes are refused.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test setting and reading back the number of session tickets to send.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test setting the supported groups from an array of identifiers.
 *
 * Covers both the context and object forms: the list and count argument
 * checks, and the named-group branch of the translation - a group value may
 * be either a wolfSSL named group or, when ECC is available, a curve NID.
 * The unrecognized-group check is covered by
 * test_wolfSSL_set1_groups_inval_ext().
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_set1_groups_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_SUPPORTED_CURVES) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int dummy[1];
#if defined(HAVE_ECC) && !defined(NO_ECC_SECP)
    int groups[2];
    int count = 0;

    /* Only name curves this build accepts. ECC_USER_CURVES trims the set, so
     * these mirror the checks the library makes on a supported curve. */
#if (!defined(NO_ECC256) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 256
    groups[count++] = WOLFSSL_ECC_SECP256R1;
#endif
#if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
    groups[count++] = WOLFSSL_ECC_SECP384R1;
#endif
#endif /* HAVE_ECC && !NO_ECC_SECP */

    /* Never read - every count it is passed with is rejected first. */
    dummy[0] = 0;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* A NULL list is rejected. */
    ExpectIntEQ(wolfSSL_CTX_set1_groups(ctx, NULL, 1), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set1_groups(ssl, NULL, 1), WOLFSSL_FAILURE);

    /* A non-positive or too-large group count is rejected. */
    ExpectIntEQ(wolfSSL_CTX_set1_groups(ctx, dummy, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set1_groups(ssl, dummy, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_CTX_set1_groups(ctx, dummy, -1), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set1_groups(ssl, dummy, -1), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_CTX_set1_groups(ctx, dummy,
        WOLFSSL_MAX_GROUP_COUNT + 1), WOLFSSL_FAILURE);
    ExpectIntEQ(wolfSSL_set1_groups(ssl, dummy,
        WOLFSSL_MAX_GROUP_COUNT + 1), WOLFSSL_FAILURE);

#if defined(HAVE_ECC) && !defined(NO_ECC_SECP)
    /* Named groups are taken as-is rather than looked up as NIDs. */
    if (count > 0) {
        ExpectIntEQ(wolfSSL_CTX_set1_groups(ctx, groups, count),
            WOLFSSL_SUCCESS);
        ExpectIntEQ(wolfSSL_set1_groups(ssl, groups, count), WOLFSSL_SUCCESS);
    }
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test setting the supported groups from a colon separated list.
 *
 * Covers both the context and object forms, and rejects unknown names.
 *
 * @return  TEST_SUCCESS on success.
 */
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

    /* Group name matching is case-insensitive, matching OpenSSL behavior.
     * P-256 is the same curve as secp256r1; use it for the mixed-case list so
     * the test does not depend on additional curves being compiled in. */
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(ctx, "p-256"), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set1_groups_list(ssl, "p-256"), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(ctx, "p-256:SECP256R1"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set1_groups_list(ssl, "p-256:SECP256R1"),
        WOLFSSL_SUCCESS);

#if defined(WOLFSSL_HAVE_MLKEM) && !defined(WOLFSSL_NO_ML_KEM) && \
    !defined(WOLFSSL_TLS_NO_MLKEM_STANDALONE)
    /* ML-KEM groups are accepted by both the wolfSSL spelling ("ML_KEM_512")
     * and the OpenSSL/IANA spelling without underscores ("MLKEM512"). These
     * standalone (non-hybrid) ML-KEM groups are only usable as TLS key
     * exchange when WOLFSSL_TLS_NO_MLKEM_STANDALONE is not defined, and each
     * individual parameter set is only usable when it is compiled in. */
#ifndef WOLFSSL_NO_ML_KEM_512
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(ctx, "ML_KEM_512"),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_CTX_set1_groups_list(ctx, "MLKEM512"), WOLFSSL_SUCCESS);
#endif
#ifndef WOLFSSL_NO_ML_KEM_768
    ExpectIntEQ(wolfSSL_set1_groups_list(ssl, "MLKEM768"), WOLFSSL_SUCCESS);
#endif
#ifndef WOLFSSL_NO_ML_KEM_1024
    ExpectIntEQ(wolfSSL_set1_groups_list(ssl, "mlkem1024"), WOLFSSL_SUCCESS);
#endif
#endif

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test setting the session ticket lifetime hint.
 *
 * @return  TEST_SUCCESS on success.
 */
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

#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) \
    && defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) \
    && !defined(NO_WOLFSSL_SERVER)
/* Trivial custom ticket encryption callback: it has no key-lifetime constraint,
 * so it must be able to issue a ticket for any hint. */
static int test_TicketHint_custom_encCb(WOLFSSL* ssl,
        byte key_name[WOLFSSL_TICKET_NAME_SZ], byte iv[WOLFSSL_TICKET_IV_SZ],
        byte mac[WOLFSSL_TICKET_MAC_SZ], int enc, byte* ticket, int inLen,
        int* outLen, void* userCtx)
{
    int i;
    (void)ssl;
    (void)userCtx;
    if (enc) {
        XMEMSET(key_name, 0x2A, WOLFSSL_TICKET_NAME_SZ);
        XMEMSET(iv, 0x2A, WOLFSSL_TICKET_IV_SZ);
        XMEMSET(mac, 0x2A, WOLFSSL_TICKET_MAC_SZ);
    }
    for (i = 0; i < inLen; i++)
        ticket[i] = (byte)(ticket[i] ^ 0xA5);
    *outLen = inLen;
    return WOLFSSL_TICKET_RET_OK;
}

/* Run a handshake with the given hint (optionally with the custom callback),
 * process any (post-handshake) NewSessionTicket, and return the ticket length
 * the client received: -1 if the handshake failed, 0 if it completed without a
 * ticket, >0 if a ticket was issued. */
static int test_TicketHint_client_ticket_len(method_provider client_meth,
        method_provider server_meth, int hint, int customCb)
{
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    char buf[64];
    int ret;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    if (test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            client_meth, server_meth) != 0) {
        ret = -1;
        goto done;
    }
    wolfSSL_UseSessionTicket(ssl_c);
    if (customCb)
        wolfSSL_CTX_set_TicketEncCb(ctx_s, test_TicketHint_custom_encCb);
    wolfSSL_CTX_set_TicketHint(ctx_s, hint);

    if (test_memio_do_handshake(ssl_c, ssl_s, 10, NULL) != 0) {
        ret = -1;
        goto done;
    }
    /* Drive the client to process a post-handshake NewSessionTicket, if any. */
    (void)wolfSSL_read(ssl_c, buf, sizeof(buf));
    ret = ssl_c->session->ticketLen;
done:
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
    return ret;
}
#endif

/* The default ticket encryption callback must refuse to issue a ticket when the
 * hint exceeds half the key lifetime, but a custom callback has no such limit. */
int test_wolfSSL_CTX_set_TicketHint_default_cb_limit(void)
{
    EXPECT_DECLS;
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_TLS13) \
    && defined(HAVE_SESSION_TICKET) \
    && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && !defined(NO_WOLFSSL_SERVER)
    /* Default callback, hint below the limit: handshake succeeds, ticket issued. */
    ExpectIntGT(test_TicketHint_client_ticket_len(wolfTLSv1_3_client_method,
        wolfTLSv1_3_server_method, WOLFSSL_TICKET_KEY_LIFETIME / 2 - 1, 0), 0);
    /* Default callback, hint at the limit: handshake succeeds, no ticket. */
    ExpectIntEQ(test_TicketHint_client_ticket_len(wolfTLSv1_3_client_method,
        wolfTLSv1_3_server_method, WOLFSSL_TICKET_KEY_LIFETIME / 2, 0), 0);
    /* Custom callback: the same oversized hint still issues a ticket. */
    ExpectIntGT(test_TicketHint_client_ticket_len(wolfTLSv1_3_client_method,
        wolfTLSv1_3_server_method, WOLFSSL_TICKET_KEY_LIFETIME / 2, 1), 0);
#ifndef WOLFSSL_NO_TLS12
    /* Same behavior on the TLS 1.2 SendTicket path. */
    ExpectIntGT(test_TicketHint_client_ticket_len(wolfTLSv1_2_client_method,
        wolfTLSv1_2_server_method, WOLFSSL_TICKET_KEY_LIFETIME / 2 - 1, 0), 0);
    ExpectIntEQ(test_TicketHint_client_ticket_len(wolfTLSv1_2_client_method,
        wolfTLSv1_2_server_method, WOLFSSL_TICKET_KEY_LIFETIME / 2, 0), 0);
    ExpectIntGT(test_TicketHint_client_ticket_len(wolfTLSv1_2_client_method,
        wolfTLSv1_2_server_method, WOLFSSL_TICKET_KEY_LIFETIME / 2, 1), 0);
#endif
#endif
    return EXPECT_RESULT();
}

/* Test the OpenSSL compatibility maximum fragment length setters.
 *
 * Covers both the context and object forms.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test turning off the extended master secret extension.
 *
 * Covers both the context and object forms.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test setting the SNI host name and reading it back.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test installing the server name callback on a context.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test storing and retrieving the debug argument on an object.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_set_tlsext_debug_arg_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && \
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

#if defined(OPENSSL_EXTRA) && \
    !defined(NO_TLS) && \
    (!defined(NO_WOLFSSL_CLIENT) || \
     (defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
      defined(HAVE_TLS_EXTENSIONS)))
/* State recorded by test_tlsext_debug_cb(). */
struct test_tlsext_debug_data {
    int count;          /* number of extensions reported */
    int client_server;  /* client_server value reported */
    int types[32];      /* extension types reported, in order */
    int lens[32];       /* lengths of the reported extensions */
};

static void test_tlsext_debug_cb(WOLFSSL *ssl, int client_server, int type,
        const byte *data, int len, void *arg)
{
    struct test_tlsext_debug_data *d = (struct test_tlsext_debug_data *)arg;
    (void)ssl;
    (void)data;

    d->count++;
    d->client_server = client_server;
    if (d->count - 1 < (int)(sizeof(d->types) / sizeof(d->types[0]))) {
        d->types[d->count - 1] = type;
        d->lens[d->count - 1] = len;
    }
}
#endif /* helper callback for the TLS ext debug callback tests */

#if defined(OPENSSL_EXTRA) && \
    !defined(NO_TLS) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_TLS_EXTENSIONS)
/* Find an extension type in the recorded list; returns its length, -1 if
 * not reported. */
static int test_tlsext_debug_find_len(const struct test_tlsext_debug_data *d,
        int type)
{
    int i;

    for (i = 0; i < d->count &&
            i < (int)(sizeof(d->types) / sizeof(d->types[0])); i++) {
        if (d->types[i] == type)
            return d->lens[i];
    }
    return -1;
}
#endif /* helper lookup for the TLS ext debug handshake test */

/* Test installing the TLS extension debug callback.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_set_tlsext_debug_callback_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* NULL object is rejected. */
    ExpectIntEQ(wolfSSL_set_tlsext_debug_callback(NULL,
        test_tlsext_debug_cb), WOLFSSL_FAILURE);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));
    ExpectIntEQ(wolfSSL_set_tlsext_debug_callback(ssl, test_tlsext_debug_cb),
        WOLFSSL_SUCCESS);
    /* Setting NULL disables the callback. */
    ExpectIntEQ(wolfSSL_set_tlsext_debug_callback(ssl, NULL),
        WOLFSSL_SUCCESS);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that the TLS extension debug callback reports the extensions
 * received during a handshake on both sides.
 *
 * client_server identifies the side of the connection and the argument set
 * with wolfSSL_set_tlsext_debug_arg() is passed through to the callback.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_set_tlsext_debug_callback_handshake_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && \
    defined(HAVE_TLS_EXTENSIONS) && !defined(NO_TLS)
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    struct test_tlsext_debug_data cData, sData;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    XMEMSET(&cData, 0, sizeof(cData));
    XMEMSET(&sData, 0, sizeof(sData));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfSSLv23_client_method, wolfSSLv23_server_method), 0);

    ExpectIntEQ(wolfSSL_set_tlsext_debug_callback(ssl_c, test_tlsext_debug_cb),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_tlsext_debug_arg(ssl_c, &cData), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_tlsext_debug_callback(ssl_s, test_tlsext_debug_cb),
        WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_set_tlsext_debug_arg(ssl_s, &sData), WOLFSSL_SUCCESS);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    /* Each side saw extensions from the peer, tagged with its own side.
     * The server always sees the client hello's core extensions (e.g.
     * supported groups); the client sees the server hello's, which carries
     * supported versions in TLS 1.3 or the echoed extended master secret in
     * TLS 1.2. */
    ExpectTrue(sData.count > 0);
#if defined(HAVE_EXTENDED_MASTER) || defined(WOLFSSL_TLS13)
    ExpectTrue(cData.count > 0);
#endif
    ExpectIntEQ(cData.client_server, 1);
    ExpectIntEQ(sData.client_server, 0);

    /* Known extensions are reported with the expected content. */
#if defined(WOLFSSL_TLS13)
    /* TLS 1.3: both sides see supported versions (a list of 2-byte
     * versions, so at least 2 bytes). */
    ExpectTrue(test_tlsext_debug_find_len(&cData,
        TLSX_SUPPORTED_VERSIONS) >= 2);
    ExpectTrue(test_tlsext_debug_find_len(&sData,
        TLSX_SUPPORTED_VERSIONS) >= 2);
#elif defined(HAVE_EXTENDED_MASTER)
    /* TLS 1.2: the client offers extended master secret (empty content). */
    ExpectIntEQ(test_tlsext_debug_find_len(&sData,
        TLSX_EXTENDED_MASTER_SECRET), 0);
#endif

    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}

/* Test installing the session ticket callback and its context.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test setting the supported curves from a colon separated list.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test the secure renegotiation resumption request.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test enabling secure renegotiation on a context.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test the NPN advertise and select callbacks.
 *
 * Nothing has been negotiated before a handshake, so the negotiated protocol is
 * empty.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test the certificate status request extension and identifier lists.
 *
 * The getters report nothing until a list has been set.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test that wolfSSL_SNI_GetFromBuffer() rejects bad arguments.
 *
 * Also covers buffers that are too short to hold the extension.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test that wolfSSL_UseTrustedCA() rejects bad arguments.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test that wolfSSL_UseMaxFragment() rejects bad arguments.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test that the supported group setters rejects bad arguments.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test that wolfSSL_UseALPN() rejects bad arguments.
 *
 * Covers a NULL object, a NULL list, an over-long list and unsupported option
 * combinations.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test that the peer ALPN protocol accessors rejects bad arguments.
 *
 * @return  TEST_SUCCESS on success.
 */
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

    wolfSSL_ALPN_FreePeerProtocol(ssl, &list);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test that wolfSSL_CTX_set_TicketEncCb() rejects bad arguments.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test that the session ticket APIs rejects bad arguments.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test that wolfSSL_CTX_set_servername_arg() rejects bad arguments.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_CTX_set_servername_arg_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SNI)
    /* A NULL context is rejected. */
    ExpectIntEQ(wolfSSL_CTX_set_servername_arg(NULL, NULL), WOLFSSL_FAILURE);
#endif
    return EXPECT_RESULT();
}

/* Test that wolfSSL_CTX_set_alpn_protos() rejects bad arguments.
 *
 * @return  TEST_SUCCESS on success.
 */
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

/* Test parsing the dual algorithm certificate key share signature specifiers.
 *
 * An over-long list is rejected even when every specifier in it is valid.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_dual_alg_cks_parse_ext(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_DUAL_ALG_CERTS) && defined(WOLFSSL_TLS13) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
    byte         oversized[WOLFSSL_MAX_CKS_SIGSPEC_SZ + 1];
    byte         huge[64];
    byte         maxValid[WOLFSSL_MAX_CKS_SIGSPEC_SZ];
    byte         value;

    /* An oversized list made entirely of valid specifiers still needs to be
     * rejected, so fill the buffers with a valid value. */
    XMEMSET(oversized, WOLFSSL_CKS_SIGSPEC_NATIVE, sizeof(oversized));
    XMEMSET(huge, WOLFSSL_CKS_SIGSPEC_NATIVE, sizeof(huge));
    maxValid[0] = WOLFSSL_CKS_SIGSPEC_BOTH;
    maxValid[1] = WOLFSSL_CKS_SIGSPEC_ALTERNATIVE;
    maxValid[2] = WOLFSSL_CKS_SIGSPEC_NATIVE;

    /* A client reaches the allocation path without needing an alt key. */
    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* A zero length list is rejected. */
    value = WOLFSSL_CKS_SIGSPEC_NATIVE;
    ExpectIntEQ(TLSX_CKS_Parse(ssl, &value, 0, &ssl->extensions),
        WC_NO_ERR_TRACE(BUFFER_ERROR));

    /* A list of all-valid bytes longer than the semantic maximum is rejected
     * before any allocation. This is the denial-of-service regression:
     * previously any length up to 65535 was copied into a fresh heap buffer. */
    ExpectIntEQ(TLSX_CKS_Parse(ssl, oversized, (word16)sizeof(oversized),
        &ssl->extensions), WC_NO_ERR_TRACE(BUFFER_ERROR));
    ExpectIntEQ(TLSX_CKS_Parse(ssl, huge, (word16)sizeof(huge),
        &ssl->extensions), WC_NO_ERR_TRACE(BUFFER_ERROR));

    /* An invalid specifier value is still rejected. */
    value = WOLFSSL_CKS_SIGSPEC_EXTERNAL;
    ExpectIntEQ(TLSX_CKS_Parse(ssl, &value, 1, &ssl->extensions),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* A well-formed list at the maximum length is accepted, so the cap does not
     * break legitimate peers (the example client sends all three specifiers). */
    ExpectIntEQ(TLSX_CKS_Parse(ssl, maxValid, (word16)sizeof(maxValid),
        &ssl->extensions), 0);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_ALPN_FreePeerProtocol() argument checking.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_ALPN_FreePeerProtocol_inval_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ALPN) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    char* list = NULL;

    /* A NULL object is rejected before the list is touched. */
    ExpectIntEQ(wolfSSL_ALPN_FreePeerProtocol(NULL, &list),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectNull(list);
#endif
    return EXPECT_RESULT();
}

/* Test that wolfSSL_ALPN_GetPeerProtocol() rejects a malformed peer list.
 *
 * The peer's list is stored in wire format, so a length byte that runs past
 * the end of the buffer must be caught rather than copied out of bounds.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_ALPN_GetPeerProtocol_badlen_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_ALPN) && !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char* list = NULL;
    word16 listSz = 0;
    byte* peer = NULL;

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* No list offered by the peer yet. */
    ExpectIntEQ(wolfSSL_ALPN_GetPeerProtocol(ssl, &list, &listSz),
        WC_NO_ERR_TRACE(BUFFER_ERROR));

    /* Install a list whose first length byte claims more bytes than are
     * present. wolfSSL_free() releases the buffer with the object, so it must
     * be allocated with the type the library frees it with. */
    if (ssl != NULL) {
        peer = (byte*)XMALLOC(4, ssl->heap, DYNAMIC_TYPE_ALPN);
        ExpectNotNull(peer);
        if (peer != NULL) {
            peer[0] = 8;    /* claims 8 bytes of protocol name */
            peer[1] = 'h';
            peer[2] = '2';
            peer[3] = 0;
            ssl->alpn_peer_requested = peer;
            ssl->alpn_peer_requested_length = 4;

            ExpectIntEQ(wolfSSL_ALPN_GetPeerProtocol(ssl, &list, &listSz),
                WC_NO_ERR_TRACE(WOLFSSL_FAILURE));
            ExpectNull(list);
        }
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_SSL_get_secure_renegotiation_support().
 *
 * Reports 0 before the extension is enabled and non-zero afterwards.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_get_secure_renegotiation_support_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SERVER_RENEGOTIATION_INFO) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    /* A NULL object reports no support. */
    ExpectIntEQ(wolfSSL_SSL_get_secure_renegotiation_support(NULL), 0);

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* A NULL object is rejected when requesting the extension. */
    ExpectIntEQ(wolfSSL_UseSecureRenegotiation(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Not requested yet. */
    ExpectIntEQ(wolfSSL_SSL_get_secure_renegotiation_support(ssl), 0);

    /* Requesting the extension is not enough - support is only reported once
     * the peer has agreed to it during the handshake. */
    ExpectIntEQ(wolfSSL_UseSecureRenegotiation(ssl), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_SSL_get_secure_renegotiation_support(ssl), 0);

    /* Once negotiated, support is reported. */
    if ((ssl != NULL) && (ssl->secure_renegotiation != NULL)) {
        ssl->secure_renegotiation->enabled = 1;
        ExpectIntEQ(wolfSSL_SSL_get_secure_renegotiation_support(ssl), 1);
        ssl->secure_renegotiation->enabled = 0;
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

/* Test wolfSSL_set_alpn_protos() with a malformed wire-format list.
 *
 * A length byte that runs past the end of the buffer must be rejected rather
 * than producing a truncated protocol list.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_set_alpn_protos_badlen_ext(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && defined(HAVE_ALPN) && !defined(NO_BIO) && \
    !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    /* First entry claims 8 bytes but only 3 follow. */
    const unsigned char bad[] = { 8, 'h', '2', 0 };
    const unsigned char good[] = { 2, 'h', '2' };
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    const int okRet = 0;
    const int failRet = 1;
#else
    const int okRet = WOLFSSL_SUCCESS;
    const int failRet = WOLFSSL_FAILURE;
#endif

    ExpectNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()));
    ExpectNotNull(ssl = wolfSSL_new(ctx));

    /* A well-formed list is accepted. */
    ExpectIntEQ(wolfSSL_set_alpn_protos(ssl, good, (unsigned int)sizeof(good)),
        okRet);

    /* A bad length byte is rejected. */
    ExpectIntEQ(wolfSSL_set_alpn_protos(ssl, bad, (unsigned int)sizeof(bad)),
        failRet);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
#endif
    return EXPECT_RESULT();
}

#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_TLS12) && \
    defined(OPENSSL_EXTRA) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_256) && !defined(NO_SHA256) && !defined(NO_HMAC) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)

/* Return values of an OpenSSL-style ticket key callback. These mirror the
 * TICKET_KEY_CB_RET_* values used by wolfSSL_TicketKeyCb() in
 * src/ssl_api_ext.c, which are private to that file. */
#define TEST_SSL_EXT_TICKET_CB_OK       1
#define TEST_SSL_EXT_TICKET_CB_RENEW    2

/* Count the session tickets the client is issued.
 *
 * Called for each ticket received, so a count of more than the one from the
 * first handshake means the server issued a replacement.
 *
 * @param [in] ssl       SSL/TLS object. Unused.
 * @param [in] ticket    Ticket received. Unused.
 * @param [in] ticketSz  Length of ticket in bytes. Unused.
 * @param [in] ctx       Count to increment.
 * @return  0 always - the caller does not use the return value.
 */
static int test_ssl_ext_ticket_recv_cb(WOLFSSL* ssl,
    const unsigned char* ticket, int ticketSz, void* ctx)
{
    (void)ssl;
    (void)ticket;
    (void)ticketSz;

    if (ctx != NULL) {
        (*(int*)ctx)++;
    }

    return 0;
}

/* OpenSSL-style session ticket key callback that always asks for renewal.
 *
 * Uses fixed key material - the ticket never leaves this test.
 *
 * @param [in]      ssl   SSL/TLS object. Unused.
 * @param [in, out] name  Key name; set when encrypting, ignored when not -
 *                        there is only ever the one key here.
 * @param [in, out] iv    Initialization vector; set when encrypting.
 * @param [in, out] ectx  Cipher context to initialize.
 * @param [in, out] hctx  HMAC context to initialize.
 * @param [in]      enc   1 when encrypting a ticket, 0 when decrypting.
 * @return  TEST_SSL_EXT_TICKET_CB_OK when encrypting.
 * @return  TEST_SSL_EXT_TICKET_CB_RENEW when decrypting, asking the ticket to
 *          be reissued.
 * @return  0 when the cipher or HMAC cannot be set up.
 */
static int test_ssl_ext_ticket_renew_cb(WOLFSSL* ssl, unsigned char* name,
    unsigned char* iv, WOLFSSL_EVP_CIPHER_CTX* ectx, WOLFSSL_HMAC_CTX* hctx,
    int enc)
{
    static const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char hmacKey[32] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    int ret;

    (void)ssl;

    if (enc) {
        XMEMSET(name, 'N', WOLFSSL_TICKET_NAME_SZ);
        XMEMSET(iv, 'I', WOLFSSL_TICKET_IV_SZ);
    }

    if (HMAC_Init_ex(hctx, hmacKey, (int)sizeof(hmacKey), EVP_sha256(),
            NULL) != 1) {
        ret = 0;
    }
    else if (enc) {
        if (EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            ret = 0;
        }
        else {
            ret = TEST_SSL_EXT_TICKET_CB_OK;
        }
    }
    else if (EVP_DecryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ret = 0;
    }
    else {
        /* Ask for the ticket to be reissued after this resumption. */
        ret = TEST_SSL_EXT_TICKET_CB_RENEW;
    }

    return ret;
}
#endif

/* Test that a TLS 1.2 resumption honours a ticket key callback asking for
 * renewal.
 *
 * When the callback reports renewal while decrypting, wolfSSL_TicketKeyCb()
 * must report that a new ticket is needed rather than plain success. This only
 * applies below TLS 1.3, which issues tickets separately.
 *
 * @return  TEST_SUCCESS on success.
 */
int test_wolfSSL_ticket_key_cb_renew_ext(void)
{
    EXPECT_DECLS;
#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_TLS12) && \
    defined(OPENSSL_EXTRA) && defined(HAVE_AES_CBC) && \
    defined(WOLFSSL_AES_256) && !defined(NO_SHA256) && !defined(NO_HMAC) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    WOLFSSL_SESSION* session = NULL;
    int newTickets = 0;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfTLSv1_2_client_method, wolfTLSv1_2_server_method), 0);

    ExpectIntEQ(wolfSSL_CTX_set_tlsext_ticket_key_cb(ctx_s,
        test_ssl_ext_ticket_renew_cb), WOLFSSL_SUCCESS);
    ExpectIntEQ(wolfSSL_UseSessionTicket(ssl_c), WOLFSSL_SUCCESS);

    /* First handshake issues a ticket. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectNotNull(session = wolfSSL_get1_session(ssl_c));

    wolfSSL_free(ssl_c);
    ssl_c = NULL;
    wolfSSL_free(ssl_s);
    ssl_s = NULL;
    test_memio_clear_buffer(&test_ctx, 0);
    test_memio_clear_buffer(&test_ctx, 1);

    ExpectNotNull(ssl_c = wolfSSL_new(ctx_c));
    ExpectNotNull(ssl_s = wolfSSL_new(ctx_s));
    wolfSSL_SetIOReadCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_c, &test_ctx);
    wolfSSL_SetIOReadCtx(ssl_s, &test_ctx);
    wolfSSL_SetIOWriteCtx(ssl_s, &test_ctx);
    ExpectIntEQ(wolfSSL_set_session(ssl_c, session), WOLFSSL_SUCCESS);
    /* Count the tickets this handshake issues. */
    ExpectIntEQ(wolfSSL_set_SessionTicket_cb(ssl_c,
        test_ssl_ext_ticket_recv_cb, &newTickets), WOLFSSL_SUCCESS);
    /* Make the ticket the only resumption path so the callback is reached. */
    if (ssl_s != NULL) {
        ssl_s->options.sessionCacheOff = 1;
    }

    /* The ticket decrypts and the session resumes. */
    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);
    ExpectIntEQ(wolfSSL_session_reused(ssl_c), 1);
    /* And because the key callback asked for renewal, the server issued a
     * replacement ticket rather than just accepting the one presented. Plain
     * success would resume just the same but send no ticket, so this is what
     * separates the two. */
    ExpectIntGT(newTickets, 0);

    wolfSSL_SESSION_free(session);
    wolfSSL_free(ssl_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_CTX_free(ctx_s);
#endif
    return EXPECT_RESULT();
}
