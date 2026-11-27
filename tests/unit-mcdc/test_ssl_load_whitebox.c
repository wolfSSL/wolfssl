/* test_ssl_load_whitebox.c
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

#include <wolfssl/options.h>
#include <src/ssl.c>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && !defined(NO_CERTS) && \
    !defined(NO_RSA) && !defined(NO_WOLFSSL_CLIENT) && \
    !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)

#ifndef USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_2048
#endif
#include <wolfssl/certs_test.h>

/* Public loaders always supply the supported object and buffer combinations.
 * Exercise the helper contracts using the same DER fixtures as the API tests. */
static int test_process_buffer(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    const byte* cert = client_cert_der_2048;
    long size = sizeof_client_cert_der_2048;
    int failed = 0;

    if (ProcessBuffer(NULL, cert, size, WOLFSSL_FILETYPE_ASN1, CA_TYPE,
            ssl, NULL, 0, VERIFY, "test certificate") != BAD_FUNC_ARG)
        failed = 1;
    if (ProcessBuffer(NULL, cert, size, -1, CA_TYPE,
            ssl, NULL, 0, VERIFY, "test certificate") != WOLFSSL_BAD_FILETYPE)
        failed = 1;
    if (ProcessBuffer(ctx, cert, size, WOLFSSL_FILETYPE_ASN1, CHAIN_CERT_TYPE,
            NULL, NULL, 0, VERIFY, "test certificate") != BAD_FUNC_ARG)
        failed = 1;
    if (ProcessBuffer(ctx, cert, size, WOLFSSL_FILETYPE_ASN1, CERT_TYPE,
            NULL, NULL, 0, VERIFY, "test certificate") != WOLFSSL_SUCCESS)
        failed = 1;
    if (ProcessBuffer(ctx, ca_cert_der_2048, sizeof_ca_cert_der_2048,
            WOLFSSL_FILETYPE_ASN1, CA_TYPE, NULL, NULL, 0, VERIFY,
            "test CA") != WOLFSSL_SUCCESS)
        failed = 1;
    if (ProcessBuffer(NULL, cert, size, WOLFSSL_FILETYPE_ASN1, CERT_TYPE,
            ssl, NULL, 0, VERIFY, "test certificate") != WOLFSSL_SUCCESS)
        failed = 1;
    return failed;
}

static int test_decode_key(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    DerBuffer* der = NULL;
    int keyFormat = RSAk;
    int failed = 0;

    if (AllocDer(&der, sizeof_client_key_der_2048, PRIVATEKEY_TYPE, NULL) != 0)
        return 1;
    XMEMCPY(der->buffer, client_key_der_2048, sizeof_client_key_der_2048);
    if (ProcessBufferTryDecode(ctx, NULL, NULL, &keyFormat, NULL,
            PRIVATEKEY_TYPE) != BAD_FUNC_ARG)
        failed = 1;
    if (ProcessBufferTryDecode(ctx, NULL, der, NULL, NULL,
            PRIVATEKEY_TYPE) != BAD_FUNC_ARG)
        failed = 1;
    if (ProcessBufferTryDecode(NULL, NULL, der, &keyFormat, NULL,
            PRIVATEKEY_TYPE) != BAD_FUNC_ARG)
        failed = 1;
    if (ProcessBufferTryDecode(ctx, NULL, der, &keyFormat, NULL,
            PRIVATEKEY_TYPE) != 0 || keyFormat != RSAk)
        failed = 1;
    keyFormat = RSAk;
    if (ProcessBufferTryDecode(NULL, ssl, der, &keyFormat, NULL,
            PRIVATEKEY_TYPE) != 0 || keyFormat != RSAk)
        failed = 1;
    FreeDer(&der);
    return failed;
}

int main(void)
{
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int failed = 1;

    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        return 1;
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    ssl = ctx != NULL ? wolfSSL_new(ctx) : NULL;
    if (ssl != NULL) {
        failed = test_process_buffer(ctx, ssl);
        failed |= test_decode_key(ctx, ssl);
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    if (failed)
        puts("ssl_load white-box: unexpected certificate or key result");
    return failed;
}
#else
int main(void)
{
    return 0;
}
#endif
