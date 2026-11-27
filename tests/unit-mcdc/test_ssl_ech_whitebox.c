/* test_ssl_ech_whitebox.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <wolfssl/options.h>
#include <src/ssl.c>
#include "mcdc_fault_alloc.h"

#if defined(HAVE_ECH) && !defined(NO_TLS) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)

/* Status is a query with no ownership transfer. Keep the extension and its
 * data scoped to the query and restore the connection list before teardown. */
static int wb_server_status(WOLFSSL* ssl)
{
    TLSX extension;
    TLSX* saved = ssl->extensions;
    WOLFSSL_ECH ech;
    byte inner = 0;
    int failed = 0;

    XMEMSET(&extension, 0, sizeof(extension));
    XMEMSET(&ech, 0, sizeof(ech));
    extension.type = TLSX_ECH;
    ech.state = ECH_WRITE_NONE;

    ssl->extensions = NULL;
    if (wolfSSL_GetEchStatus(ssl) != WOLFSSL_ECH_STATUS_NOT_OFFERED)
        failed = 1;
    ssl->extensions = &extension;
    if (wolfSSL_GetEchStatus(ssl) != WOLFSSL_ECH_STATUS_NOT_OFFERED)
        failed = 1;
    extension.data = &ech;
    if (wolfSSL_GetEchStatus(ssl) != WOLFSSL_ECH_STATUS_NOT_OFFERED)
        failed = 1;
    ech.state = ECH_WRITE_RETRY_CONFIGS;
    if (wolfSSL_GetEchStatus(ssl) != WOLFSSL_ECH_STATUS_REJECTED)
        failed = 1;
    ech.state = ECH_WRITE_NONE;
    ech.innerClientHello = &inner;
    if (wolfSSL_GetEchStatus(ssl) != WOLFSSL_ECH_STATUS_REJECTED)
        failed = 1;

    ssl->extensions = saved;
    return failed;
}

#if defined(HAVE_ECC) && !defined(NO_ECC256) && defined(HAVE_AESGCM)
/* A well-formed config with a reserved algorithm or version must be
 * ignored. Subsequent parsing should still accept the generated config. */
static int wb_config_selection(WOLFSSL_CTX* ctx)
{
    WOLFSSL_EchConfig candidate = *ctx->echConfigs;
    WOLFSSL_EchConfig* parsed = NULL;
    EchCipherSuite reserved = { 0xffff, 0xffff };
    byte wire[512];
    word32 length = sizeof(wire) - 2;
    int failed = 0;

    candidate.cipherSuites = &reserved;
    candidate.numCipherSuites = 1;
    if (wolfSSL_local_GetEchConfig(&candidate, wire + 2, &length) != 0)
        return 1;
    c16toa((word16)length, wire);
    if (wolfSSL_local_SetEchConfigsEx(&parsed, ctx->heap, wire, length + 2) !=
            UNSUPPORTED_SUITE || parsed != NULL)
        failed = 1;
    wolfSSL_local_FreeEchConfigs(parsed, ctx->heap);
    parsed = NULL;

    /* RFC 8701 reserves 0x0a0a for exercising extensibility. */
    c16toa(0x0a0a, wire + 2);
    if (wolfSSL_local_SetEchConfigsEx(&parsed, ctx->heap, wire, length + 2) !=
            UNSUPPORTED_PROTO_VERSION || parsed != NULL)
        failed = 1;
    wolfSSL_local_FreeEchConfigs(parsed, ctx->heap);
    parsed = NULL;

    length = sizeof(wire);
    if (wolfSSL_CTX_GetEchConfigs(ctx, wire, &length) != WOLFSSL_SUCCESS)
        return 1;
#ifndef MCDC_FA_UNAVAILABLE
    mcdc_fa_install();
    mcdc_fa_arm_only(1);
    if (wolfSSL_local_SetEchConfigsEx(&parsed, ctx->heap, wire, length) !=
            MEMORY_E || parsed != NULL)
        failed = 1;
    mcdc_fa_restore();
    wolfSSL_local_FreeEchConfigs(parsed, ctx->heap);
    parsed = NULL;
#endif
    if (wolfSSL_local_SetEchConfigsEx(&parsed, ctx->heap, wire, length) != 0 ||
            parsed == NULL)
        failed = 1;
    wolfSSL_local_FreeEchConfigs(parsed, ctx->heap);
    return failed;
}

static int wb_config_queries(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    WOLFSSL_EchConfig config;
    char tooLong[257];
    byte retry[512];
    word32 size = 0;
    int failed = 0;

    XMEMSET(&config, 0, sizeof(config));
    config.kemId = DHKEM_P256_HKDF_SHA256;
    XMEMSET(tooLong, 'a', sizeof(tooLong) - 1);
    tooLong[sizeof(tooLong) - 1] = '\0';

    if (wolfSSL_local_GetEchConfig(&config, NULL, &size) != BAD_FUNC_ARG)
        failed = 1;
    config.publicName = tooLong;
    if (wolfSSL_local_GetEchConfig(&config, NULL, &size) != BAD_FUNC_ARG)
        failed = 1;

    if (wolfSSL_CTX_GenerateEchConfig(ctx, "example.com",
            DHKEM_P256_HKDF_SHA256, HKDF_SHA256, HPKE_AES_128_GCM) !=
            WOLFSSL_SUCCESS)
        return 1;
    if (wolfSSL_local_GetEchConfig(ctx->echConfigs, NULL, &size) != LENGTH_ONLY_E
            || size == 0)
        failed = 1;

    /* Receiving a config is insufficient until the retry is authenticated. */
    ssl->echRetryConfigs = ctx->echConfigs;
    size = sizeof(retry);
    if (wolfSSL_GetEchRetryConfigs(ssl, retry, &size) != WOLFSSL_FATAL_ERROR)
        failed = 1;
    ssl->options.echRetryConfigsAccepted = 1;
    if (wolfSSL_GetEchRetryConfigs(ssl, retry, &size) != WOLFSSL_SUCCESS)
        failed = 1;
    ssl->options.echRetryConfigsAccepted = 0;
    ssl->echRetryConfigs = NULL;
    return failed | wb_config_selection(ctx);
}
#endif

int main(void)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int failed = 1;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        return 1;
    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    if (ctx == NULL)
        goto done;
    /* A temporary server needs no credentials for these queries. */
    ssl = (WOLFSSL*)XMALLOC(sizeof(*ssl), ctx->heap, DYNAMIC_TYPE_SSL);
    if (ssl == NULL)
        goto done;
    XMEMSET(ssl, 0, sizeof(*ssl));
    ssl->options.side = WOLFSSL_SERVER_END;
    failed = wb_server_status(ssl);
#if defined(HAVE_ECC) && !defined(NO_ECC256) && defined(HAVE_AESGCM)
    failed |= wb_config_queries(ctx, ssl);
#endif

done:
    XFREE(ssl, ctx != NULL ? ctx->heap : NULL, DYNAMIC_TYPE_SSL);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    if (failed)
        puts("ssl_ech white-box: unexpected status or config query result");
    return failed;
}

#else

int main(void)
{
    return 0;
}

#endif
