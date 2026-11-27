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

static int test_copy_chain_entry(WOLFSSL_CTX* ctx)
{
    DerBuffer* der = NULL;
    byte output[sizeof(ca_cert_der_2048) + CERT_HEADER_SZ];
    word32 index = 0;
    int failed = 0;

    if (AllocCopyDer(&der, ca_cert_der_2048, sizeof_ca_cert_der_2048,
            CERT_TYPE, ctx->heap) != 0)
        return 1;
    if (ProcessUserCert(ctx->cm, &der, CERT_TYPE, VERIFY, output, &index,
            sizeof(output) - 1) != BUFFER_E || index != 0)
        failed = 1;
    if (ProcessUserCert(ctx->cm, &der, CERT_TYPE, VERIFY, output, &index,
            sizeof(output)) != 0 || index != sizeof(output) ||
        XMEMCMP(output + CERT_HEADER_SZ, ca_cert_der_2048,
            sizeof_ca_cert_der_2048) != 0)
        failed = 1;
    FreeDer(&der);
    return failed;
}

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) && \
    !defined(NO_CODING) && !defined(WOLFSSL_NO_PEM) && defined(WOLFSSL_PEM_TO_DER)
static int test_detect_certificate_file(WOLFSSL_CTX* ctx)
{
    int failed = 0;

    if (ProcessFile(ctx, "./certs/ca-cert.pem", WOLFSSL_FILETYPE_PEM,
            DETECT_CERT_TYPE, NULL, 0, NULL, VERIFY) != WOLFSSL_SUCCESS)
        failed = 1;
    if (ProcessFile(ctx, "./certs/server-key.pem", WOLFSSL_FILETYPE_PEM,
            DETECT_CERT_TYPE, NULL, 0, NULL, VERIFY) != WOLFSSL_BAD_CERTTYPE)
        failed = 1;
    if (ProcessFile(ctx, "./certs/ca-cert.der", WOLFSSL_FILETYPE_ASN1,
            DETECT_CERT_TYPE, NULL, 0, NULL, VERIFY) != WOLFSSL_BAD_CERTTYPE)
        failed = 1;
    if (ProcessFile(ctx, "./certs/ca-cert.der", WOLFSSL_FILETYPE_ASN1,
            CA_TYPE, NULL, 0, NULL, VERIFY) != WOLFSSL_SUCCESS)
        failed = 1;
    if (ProcessFile(ctx, "./certs/does-not-exist", WOLFSSL_FILETYPE_PEM,
            DETECT_CERT_TYPE, NULL, 0, NULL, VERIFY) != WOLFSSL_BAD_FILE)
        failed = 1;
#ifdef HAVE_CRL
    if (wolfSSL_CTX_EnableCRL(ctx, WOLFSSL_CRL_CHECK) != WOLFSSL_SUCCESS)
        failed = 1;
    else if (ProcessFile(ctx, "./certs/crl/crl.pem", WOLFSSL_FILETYPE_PEM,
            DETECT_CERT_TYPE, NULL, 0, ctx->cm->crl, VERIFY_SKIP_DATE) !=
            WOLFSSL_SUCCESS)
        failed = 1;
#endif
    return failed;
}
#endif

#if defined(WOLFSSL_SYS_CA_CERTS) && !defined(USE_WINDOWS_API) && \
    !defined(__APPLE__) && !defined(NO_FILESYSTEM) && \
    !defined(NO_WOLFSSL_DIR) && defined(WOLFSSL_PEM_TO_DER)
#ifndef NO_ASN_TIME
static time_t test_system_ca_time(time_t* now)
{
    /* 2026-01-01 UTC, within the bundled external roots' validity. */
    time_t sample = (time_t)1767225600;
    if (now != NULL)
        *now = sample;
    return sample;
}
#endif

static int test_system_ca_search(WOLFSSL_CTX* ctx)
{
    const char* saved[sizeof(systemCaDirs) / sizeof(systemCaDirs[0])];
    byte loaded = 0;
    size_t i;
    int failed = 0;

    if (LoadSystemCaCertsNix(NULL, &loaded) != WOLFSSL_FAILURE ||
        LoadSystemCaCertsNix(ctx, NULL) != WOLFSSL_FAILURE ||
        wolfSSL_CTX_load_system_CA_certs(NULL) != WOLFSSL_FAILURE)
        failed = 1;

    /* Give every entry a file path so the exhaustive search is independent
     * of the host trust store. A test directory then supplies one success. */
    for (i = 0; i < sizeof(saved) / sizeof(saved[0]); i++) {
        saved[i] = systemCaDirs[i];
        systemCaDirs[i] = "./certs/ca-cert.der";
    }
    if (wolfSSL_CTX_load_system_CA_certs(ctx) != WOLFSSL_BAD_PATH)
        failed = 1;

    systemCaDirs[0] = "./certs/external";
#ifndef NO_ASN_TIME
    (void)wc_SetTimeCb(test_system_ca_time);
#endif
    if (LoadSystemCaCertsNix(ctx, &loaded) != WOLFSSL_SUCCESS || loaded != 1 ||
        wolfSSL_CTX_load_system_CA_certs(ctx) != WOLFSSL_SUCCESS)
        failed = 1;
#ifndef NO_ASN_TIME
    (void)wc_SetTimeCb(NULL);
#endif
    for (i = 0; i < sizeof(saved) / sizeof(saved[0]); i++)
        systemCaDirs[i] = saved[i];
    return failed;
}
#endif

#ifndef WC_STRICT_SIG
static int test_cert_public_key(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    DecodedCert* cert = (DecodedCert*)XMALLOC(sizeof(*cert), ctx->heap,
        DYNAMIC_TYPE_DCERT);
    int failed = 1;

    if (cert == NULL)
        return 1;
    InitDecodedCert(cert, ca_cert_der_2048, sizeof_ca_cert_der_2048, ctx->heap);
    if (DecodeToKey(cert, 0) < 0)
        goto done;

    ProcessBufferCertSetHave(NULL, NULL, cert);
    ProcessBufferCertSetHave(ctx, NULL, cert);
    ProcessBufferCertSetHave(NULL, ssl, cert);
    if (ProcessBufferCertPublicKey(NULL, NULL, cert, 1) != BAD_FUNC_ARG ||
        ProcessBufferCertPublicKey(ctx, NULL, cert, 1) != 0 ||
        ProcessBufferCertPublicKey(NULL, ssl, cert, 1) != 0 ||
        !ctx->haveRSA || !ssl->options.haveRSA)
        goto done;
    failed = 0;

done:
    FreeDecodedCert(cert);
    XFREE(cert, ctx->heap, DYNAMIC_TYPE_DCERT);
    return failed;
}
#endif

#ifndef NO_DH
static int test_tmp_dh_helper(WOLFSSL_CTX* ctx)
{
    unsigned char p[1] = { 23 };
    unsigned char g[1] = { 2 };
    word16 min = ctx->minDhKeySz;
    int failed = 0;

    /* Public adapters have already checked pointers before this helper. */
    if (wolfssl_ctx_set_tmp_dh(NULL, p, sizeof(p), g, sizeof(g)) !=
            BAD_FUNC_ARG ||
        wolfssl_ctx_set_tmp_dh(ctx, NULL, sizeof(p), g, sizeof(g)) !=
            BAD_FUNC_ARG ||
        wolfssl_ctx_set_tmp_dh(ctx, p, sizeof(p), NULL, sizeof(g)) !=
            BAD_FUNC_ARG)
        failed = 1;
    /* The minimum is checked before the helper can retain either pointer. */
    ctx->minDhKeySz = 1;
    if (wolfssl_ctx_set_tmp_dh(ctx, p, 0, g, sizeof(g)) != DH_KEY_SIZE_E)
        failed = 1;
    ctx->minDhKeySz = min;
    return failed;
}
#endif

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
#ifndef WC_STRICT_SIG
        failed |= test_cert_public_key(ctx, ssl);
#endif
#if defined(WOLFSSL_SYS_CA_CERTS) && !defined(USE_WINDOWS_API) && \
    !defined(__APPLE__) && !defined(NO_FILESYSTEM) && \
    !defined(NO_WOLFSSL_DIR) && defined(WOLFSSL_PEM_TO_DER)
        failed |= test_system_ca_search(ctx);
#endif
        failed |= test_copy_chain_entry(ctx);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) && \
    !defined(NO_CODING) && !defined(WOLFSSL_NO_PEM) && defined(WOLFSSL_PEM_TO_DER)
        failed |= test_detect_certificate_file(ctx);
#endif
#ifndef NO_DH
        failed |= test_tmp_dh_helper(ctx);
#endif
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
