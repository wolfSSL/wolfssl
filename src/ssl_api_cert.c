/* ssl_api_cert.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if !defined(WOLFSSL_SSL_API_CERT_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_api_cert.c is not compiled separately from ssl.c
    #endif
#else

#ifndef NO_CERTS

/* Set whether mutual authentication is required for connections.
 * Server side only.
 *
 * @param [in] ctx  The SSL/TLS CTX object.
 * @param [in] req  1 to indicate required and 0 when not.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 * @return  SIDE_ERROR when not a server.
 */
int wolfSSL_CTX_mutual_auth(WOLFSSL_CTX* ctx, int req)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;
    if (ctx->method->side != WOLFSSL_SERVER_END)
        return SIDE_ERROR;

    ctx->mutualAuth = (byte)req;

    return 0;
}

/* Set whether mutual authentication is required for the connection.
 * Server side only.
 *
 * @param [in] ssl  The SSL/TLS object.
 * @param [in] req  1 to indicate required and 0 when not.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  SIDE_ERROR when not a server
 */
int wolfSSL_mutual_auth(WOLFSSL* ssl, int req)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;
    if (ssl->options.side != WOLFSSL_SERVER_END)
        return SIDE_ERROR;

    ssl->options.mutualAuth = (word16)req;

    return 0;
}

/* Get the certificate manager from the WOLFSSL_CTX.
 *
 * @param [in] ctx  SSL/TLS CTX object.
 * @return  Certificate manager object on success.
 * @return  NULL when ctx is NULL.
 */
WOLFSSL_CERT_MANAGER* wolfSSL_CTX_GetCertManager(WOLFSSL_CTX* ctx)
{
    WOLFSSL_CERT_MANAGER* cm = NULL;

    if (ctx)
        cm = ctx->cm;

    return cm;
}

/* Sets the max chain depth when verifying a certificate chain.
 *
 * Default depth is set to MAX_CHAIN_DEPTH.
 *
 * @param [in] ctx    WOLFSSL_CTX structure to set depth in
 * @param [in] depth  max depth
 */
void wolfSSL_CTX_set_verify_depth(WOLFSSL_CTX *ctx, int depth)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_verify_depth");

    if ((ctx == NULL) || (depth < 0) || (depth > MAX_CHAIN_DEPTH)) {
        WOLFSSL_MSG("Bad depth argument, too large or less than 0");
    }
    else {
        ctx->verifyDepth = (byte)depth;
    }
}


/* Get certificate chaining depth of SSL/TLS context object
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  Verification depth on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx)
{
    long ret;

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
    #ifndef OPENSSL_EXTRA
        ret = MAX_CHAIN_DEPTH;
    #else
        ret = ctx->verifyDepth;
    #endif
    }

    return ret;
}

/* Get certificate chaining depth of SSL/TLS object
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Verification depth on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
long wolfSSL_get_verify_depth(WOLFSSL* ssl)
{
    long ret;

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
    #ifndef OPENSSL_EXTRA
        ret = MAX_CHAIN_DEPTH;
    #else
        ret = ssl->options.verifyDepth;
    #endif
    }

    return ret;
}

#if defined(HAVE_RPK)
/* TODO: Change this to use a bitfield. */

/* Confirm that all the byte data in the buffer is unique.
 *
 * @param [in] buf  Buffer to check.
 * @param [in] len  Length of buffer in bytes.
 * @return  1 if all the byte data in the buffer is unique.
 * @return  0 otherwise.
 */
static int isArrayUnique(const char* buf, size_t len)
{
    size_t i;
    /* check the array is unique */
    for (i = 0; i < len - 1; ++i) {
        size_t j;
        for (j = i + 1; j < len; ++j) {
            if (buf[i] == buf[j]) {
                return 0;
            }
        }
    }
    return 1;
}
/* Set user preference for the {client,server}_cert_type extension.
 *
 * Takes byte array containing cert types the caller can provide to its peer.
 * Cert types are in preferred order in the array.
 *
 * @param [in] cfg     Raw Public Key configuration.
 * @param [in] client  Indicates whether this is the client side.
 * @param [in] buf     List of certificate types.
 * @param [in] len     Length of certificate types.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when cfg is NULL.
 * @return  BAD_FUNC_ARG when len is too long.
 * @return  BAD_FUNC_ARG when buffer values are not unique.
 * @return  BAD_FUNC_ARG when buffer contains unrecognized certificate type.
 */
static int set_cert_type(RpkConfig* cfg, int client, const char* buf,
    int len)
{
    int i;
    byte* certTypeCnt;
    byte* certTypes;

    /* Validate parameters. */
    if ((cfg == NULL) || (len > (client ? MAX_CLIENT_CERT_TYPE_CNT :
                                          MAX_SERVER_CERT_TYPE_CNT))) {
        return BAD_FUNC_ARG;
    }

    /* Get preferred certificate types for side. */
    if (client) {
        certTypeCnt = &cfg->preferred_ClientCertTypeCnt;
        certTypes   =  cfg->preferred_ClientCertTypes;
    }
    else {
        certTypeCnt = &cfg->preferred_ServerCertTypeCnt;
        certTypes   =  cfg->preferred_ServerCertTypes;
    }
    /* If no buffer or empty buffer passed in, set the defaults. */
    if ((buf == NULL) || (len == 0)) {
        *certTypeCnt = 1;
        for (i = 0; i < 2; i++) {
            certTypes[i] = WOLFSSL_CERT_TYPE_X509;
        }
        return 1;
    }

    /* Check that the certificate types set are unique. */
    if (!isArrayUnique(buf, (size_t)len))
        return BAD_FUNC_ARG;

    /* Check that the certificate types being set are known and then set. */
    for (i = 0; i < len; i++) {
        if ((buf[i] != WOLFSSL_CERT_TYPE_RPK) &&
                (buf[i] != WOLFSSL_CERT_TYPE_X509)) {
            return BAD_FUNC_ARG;
        }
        certTypes[i] = (byte)buf[i];
    }
    *certTypeCnt = len;

    return 1;
}
/* Set the client certificate types against the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] buf  List of certificate types.
 * @param [in] len  Length of certificate types.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 * @return  BAD_FUNC_ARG when len is too long.
 * @return  BAD_FUNC_ARG when buffer values are not unique.
 * @return  BAD_FUNC_ARG when buffer contains unrecognized certificate type.
 */
int wolfSSL_CTX_set_client_cert_type(WOLFSSL_CTX* ctx, const char* buf, int len)
{
    int ret;

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = set_cert_type(&ctx->rpkConfig, 1, buf, len);
    }

    return ret;
}
/* Set the server certificate types against the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] buf  List of certificate types.
 * @param [in] len  Length of certificate types.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 * @return  BAD_FUNC_ARG when len is too long.
 * @return  BAD_FUNC_ARG when buffer values are not unique.
 * @return  BAD_FUNC_ARG when buffer contains unrecognized certificate type.
 */
int wolfSSL_CTX_set_server_cert_type(WOLFSSL_CTX* ctx, const char* buf, int len)
{
    int ret;

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = set_cert_type(&ctx->rpkConfig, 0, buf, len);
    }

    return ret;
}
/* Set the client certificate types against the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] buf  List of certificate types.
 * @param [in] len  Length of certificate types.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  BAD_FUNC_ARG when len is too long.
 * @return  BAD_FUNC_ARG when buffer values are not unique.
 * @return  BAD_FUNC_ARG when buffer contains unrecognized certificate type.
 */
int wolfSSL_set_client_cert_type(WOLFSSL* ssl, const char* buf, int len)
{
    int ret;

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = set_cert_type(&ssl->options.rpkConfig, 1, buf, len);
    }

    return ret;
}
/* Set the server certificate types against the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] buf  List of certificate types.
 * @param [in] len  Length of certificate types.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  BAD_FUNC_ARG when len is too long.
 * @return  BAD_FUNC_ARG when buffer values are not unique.
 * @return  BAD_FUNC_ARG when buffer contains unrecognized certificate type.
 */
int wolfSSL_set_server_cert_type(WOLFSSL* ssl, const char* buf, int len)
{
    int ret;

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = set_cert_type(&ssl->options.rpkConfig, 0, buf, len);
    }

    return ret;
}

/* Get negotiated client certificate type value.
 *
 * WOLFSSL_CERT_TYPE_UNKNOWN returned when no negotiation has been performed.
 *
 * @param [in]  ssl  SSL/TLS object.
 * @param [out] tp   Certificate type. One of:
 *                     -1: WOLFSSL_CERT_TYPE_UNKNOWN
 *                      0: WOLFSSL_CERT_TYPE_X509
 *                      2: WOLFSSL_CERT_TYPE_RPK
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ssl or tp is NULL.
 */
int wolfSSL_get_negotiated_client_cert_type(WOLFSSL* ssl, int* tp)
{
    int ret = 1;

    /* Validate parameters. */
    if ((ssl == NULL) || (tp == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check side. */
    else if (ssl->options.side == WOLFSSL_CLIENT_END) {
        /* Check certificate type negotiated. */
        if (ssl->options.rpkState.received_ClientCertTypeCnt == 1) {
            *tp = ssl->options.rpkState.received_ClientCertTypes[0];
        }
        else {
            *tp = WOLFSSL_CERT_TYPE_UNKNOWN;
        }
    }
    /* Check certificate type negotiated. */
    else if (ssl->options.rpkState.sending_ClientCertTypeCnt == 1) {
        *tp = ssl->options.rpkState.sending_ClientCertTypes[0];
    }
    else {
        *tp = WOLFSSL_CERT_TYPE_UNKNOWN;
    }

    return ret;
}

/* Get negotiated server certificate type value.
 *
 * WOLFSSL_CERT_TYPE_UNKNOWN returned when no negotiation has been performed.
 *
 * @param [in]  ssl  SSL/TLS object.
 * @param [out] tp   Certificate type. One of:
 *                     -1: WOLFSSL_CERT_TYPE_UNKNOWN
 *                      0: WOLFSSL_CERT_TYPE_X509
 *                      2: WOLFSSL_CERT_TYPE_RPK
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ssl or tp is NULL.
 */
int wolfSSL_get_negotiated_server_cert_type(WOLFSSL* ssl, int* tp)
{
    int ret = 1;

    /* Validate parameters. */
    if ((ssl == NULL) || (tp == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check side. */
    else if (ssl->options.side == WOLFSSL_CLIENT_END) {
        /* Check certificate type negotiated. */
        if (ssl->options.rpkState.received_ServerCertTypeCnt == 1) {
            *tp = ssl->options.rpkState.received_ServerCertTypes[0];
        }
        else {
            *tp = WOLFSSL_CERT_TYPE_UNKNOWN;
        }
    }
    /* Check certificate type negotiated. */
    else if (ssl->options.rpkState.sending_ServerCertTypeCnt == 1) {
        *tp = ssl->options.rpkState.sending_ServerCertTypes[0];
    }
    else {
        *tp = WOLFSSL_CERT_TYPE_UNKNOWN;
    }
    return ret;
}
#endif /* HAVE_RPK */

/* Certificate verification options. */
typedef struct {
    /* Verify the peer certificate. */
    byte verifyPeer:1;
    /* No peer certificate verification. */
    byte verifyNone:1;
    /* Fail when no peer certificate seen. */
    byte failNoCert:1;
    /* Fail when no peer certificate except when PSK handshake performed. */
    byte failNoCertxPSK:1;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    /* Verify peer certificate post handshake. */
    byte verifyPostHandshake:1;
#endif
} SetVerifyOptions;

/* Convert the mode flags into certificate verification options.
 *
 * @param [in] mode  Certificate verification mode flags.
 * @return  Certificate verification options.
 */
static SetVerifyOptions ModeToVerifyOptions(int mode)
{
    SetVerifyOptions opts;

    /* Set the options to the default - none set. */
    XMEMSET(&opts, 0, sizeof(SetVerifyOptions));

    /* When the mode is not default - set the options. */
    if (mode != WOLFSSL_VERIFY_DEFAULT) {
        opts.verifyNone = (mode == WOLFSSL_VERIFY_NONE);
        /* When not no verification, set the chosen options. */
        if (!opts.verifyNone) {
            opts.verifyPeer          =
                    (mode & WOLFSSL_VERIFY_PEER) != 0;
            opts.failNoCertxPSK      =
                    (mode & WOLFSSL_VERIFY_FAIL_EXCEPT_PSK) != 0;
            opts.failNoCert          =
                    (mode & WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT) != 0;
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
            opts.verifyPostHandshake =
                    (mode & WOLFSSL_VERIFY_POST_HANDSHAKE) != 0;
#endif
        }
    }

    return opts;
}

/* Set the verification options against the SSL/TLS context.
 *
 * @param [in] ctx              SSL/TLS context object.
 * @param [in] mode             Verification mode options.
 * @param [in] verify_callback  Verification callback.
 */
WOLFSSL_ABI void wolfSSL_CTX_set_verify(WOLFSSL_CTX* ctx, int mode,
    VerifyCallback verify_callback)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_verify");

    /* Ensure we have an SSL/TLS context to work with. */
    if (ctx != NULL) {
        SetVerifyOptions opts = ModeToVerifyOptions(mode);

        /* Set the bitfield options. */
        ctx->verifyNone     = opts.verifyNone;
        ctx->verifyPeer     = opts.verifyPeer;
        ctx->failNoCert     = opts.failNoCert;
        ctx->failNoCertxPSK = opts.failNoCertxPSK;
    #if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
        ctx->verifyPostHandshake = opts.verifyPostHandshake;
    #endif

        /* Store the user verification callback against the context. */
        ctx->verifyCallback = verify_callback;
    }
}

#ifdef OPENSSL_ALL
/* Set certificate verification callback and context against SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] cb   Certificate verification callback.
 * @param [in] arg  Context for certification verification callback.
 */
void wolfSSL_CTX_set_cert_verify_callback(WOLFSSL_CTX* ctx,
    CertVerifyCallback cb, void* arg)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_cert_verify_callback");

    /* Ensure we have an SSL/TLS context to work with. */
    if (ctx != NULL) {
        ctx->verifyCertCb = cb;
        ctx->verifyCertCbArg = arg;
    }
}
#endif

/* Set the verification options against the SSL/TLS object.
 *
 * @param [in] ssl              SSL/TLS object.
 * @param [in] mode             Verification mode options.
 * @param [in] verify_callback  Verification callback.
 */
void wolfSSL_set_verify(WOLFSSL* ssl, int mode, VerifyCallback verify_callback)
{
    WOLFSSL_ENTER("wolfSSL_set_verify");

    /* Ensure we have an SSL/TLS object to work with. */
    if (ssl != NULL) {
        SetVerifyOptions opts = ModeToVerifyOptions(mode);

        /* Set the bitfield options. */
        ssl->options.verifyNone = opts.verifyNone;
        ssl->options.verifyPeer = opts.verifyPeer;
        ssl->options.failNoCert = opts.failNoCert;
        ssl->options.failNoCertxPSK = opts.failNoCertxPSK;
    #if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
        ssl->options.verifyPostHandshake = opts.verifyPostHandshake;
    #endif

        /* Store the user verification callback against the object. */
        ssl->verifyCallback = verify_callback;
    }
}

/* Set the certificate verification result for the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] v    Verification result.
 */
void wolfSSL_set_verify_result(WOLFSSL *ssl, long v)
{
    WOLFSSL_ENTER("wolfSSL_set_verify_result");

    /* Ensure we have an SSL/TLS object to work with. */
    if (ssl != NULL) {
    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        ssl->peerVerifyRet = (unsigned long)v;
    #else
        WOLFSSL_STUB("wolfSSL_set_verify_result");
        (void)v;
    #endif
    }
}

/* Store user ctx for verify callback into SSL/TLS context.
 *
 * @param [in] ctx      SSL/TLS context.
 * @param [in] userCtx  User context for verify callback.
 */
void wolfSSL_CTX_SetCertCbCtx(WOLFSSL_CTX* ctx, void* userCtx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetCertCbCtx");

    /* Validate parameters. */
    if (ctx != NULL) {
        ctx->verifyCbCtx = userCtx;
    }
}

/* Store user ctx for verify callback into SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  User context for verify callback.
 */
void wolfSSL_SetCertCbCtx(WOLFSSL* ssl, void* ctx)
{
    WOLFSSL_ENTER("wolfSSL_SetCertCbCtx");

    /* Validate parameters. */
    if (ssl != NULL) {
        ssl->verifyCbCtx = ctx;
    }
}



/* Store context CA Cache addition callback into SSL/TLS context.
 *
 * @param [in] ctx      SSL/TLS context.
 * @param [in] userCtx  User context for verify callback.
 */
void wolfSSL_CTX_SetCACb(WOLFSSL_CTX* ctx, CallbackCACache cb)
{
    /* Validate parameters. */
    if ((ctx != NULL) && (ctx->cm != NULL)) {
        ctx->cm->caCacheCallback = cb;
    }
}

#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_TLS13) && \
    defined(WOLFSSL_POST_HANDSHAKE_AUTH)
/* For TLS v1.3, send authentication messages after handshake completes.
 *
 * @return  1 on success.
 * @return  UNSUPPORTED_PROTO_VERSION when not a TLSv1.3 handshake.
 * @return  0 on other failure.
 */
int wolfSSL_verify_client_post_handshake(WOLFSSL* ssl)
{
    int ret;

    /* Do request of certificate. */
    ret = wolfSSL_request_certificate(ssl);
    if (ret != 1) {
        /* Special logging for wrong protocol version. */
        if ((ssl != NULL) && !IsAtLeastTLSv1_3(ssl->version)) {
            WOLFSSL_ERROR(UNSUPPORTED_PROTO_VERSION);
        }
        else {
            /* Other errors - return 0. */
            WOLFSSL_ERROR(ret);
        }
        ret = 0;
    }

    return ret;
}

/* Set whether handshakes from this SSL/TLS context allow auth post handshake.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] val  Whether to allow post handshake authentication.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_set_post_handshake_auth(WOLFSSL_CTX* ctx, int val)
{
    int ret;

    /* Try to allow - really just checking conditions. */
    if (wolfSSL_CTX_allow_post_handshake_auth(ctx) == 0) {
        /* Set value as a bit. */
        ctx->postHandshakeAuth = (val != 0);
        ret = 1;
    }
    else {
        ret = 0;
    }

    return ret;
}
/* Set whether handshakes with this SSL/TLS object allow auth post handshake.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] val  Whether to allow post handshake authentication.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_set_post_handshake_auth(WOLFSSL* ssl, int val)
{
    int ret;

    /* Try to allow - really just checking conditions. */
    if (wolfSSL_allow_post_handshake_auth(ssl) == 0) {
        /* Set value as a bit. */
        ssl->options.postHandshakeAuth = (val != 0);
        ret = 1;
    }
    else {
        ret = 0;
    }

    return ret;
}
#endif /* OPENSSL_EXTRA && WOLFSSL_TLS13 && WOLFSSL_POST_HANDSHAKE_AUTH */

#if defined(PERSIST_CERT_CACHE)

#if !defined(NO_FILESYSTEM)

/* Persist certificate cache in SSL/TLS context to file.
 *
 * @param [in] ctx    SSL/TLS context.
 * @param [in] fname  Filename so store certificate cache to.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx or fname is NULL.
 * @return  Other values on failure.
 */
int wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX* ctx, const char* fname)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_save_cert_cache");

    /* Validate parameters. */
    if ((ctx == NULL) || (fname == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Save certificate cache. */
        ret = CM_SaveCertCache(ctx->cm, fname);
    }

    return ret;
}


/* Load certificate cache into SSL/TLS context from file.
 *
 * @param [in] ctx    SSL/TLS context.
 * @param [in] fname  Filename so store certificate cache to.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx or fname is NULL.
 * @return  Other values on failure.
 */
int wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX* ctx, const char* fname)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_restore_cert_cache");

    /* Validate parameters. */
    if ((ctx == NULL) || (fname == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Restore certificate cache. */
        ret = CM_RestoreCertCache(ctx->cm, fname);
    }

    return ret;
}

#endif /* NO_FILESYSTEM */

/* Persist certificate cache in SSL/TLS context to memory.
 *
 * @param [in]  ctx   SSL/TLS context.
 * @param [in]  mem   Memory to fill with certificate cache.
 * @param [in]  sz    Size of memory to fill in bytes.
 * @param [out] used  The number of bytes of memory used.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx, mem or used is NULL.
 * @return  BAD_FUNC_ARG when sz is less than or equal to zero.
 * @return  Other values on failure.
 */
int wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX* ctx, void* mem,
                                   int sz, int* used)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_memsave_cert_cache");

    /* Validate parameters. */
    if ((ctx == NULL) || (mem == NULL) || (used == NULL) || (sz <= 0)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Persist certificate change to memory. */
        ret = CM_MemSaveCertCache(ctx->cm, mem, sz, used);
    }

    return ret;
}


/* Load certificate cache into SSL/TLS context from memory.
 *
 * @param [in]  ctx   SSL/TLS context.
 * @param [in]  mem   Memory with certificate cache.
 * @param [in]  sz    Size of certificate cache in bytes
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx or mem is NULL.
 * @return  BAD_FUNC_ARG when sz is less than or equal to zero.
 * @return  Other values on failure.
 */
int wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX* ctx, const void* mem, int sz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_memrestore_cert_cache");

    /* Validate parameters. */
    if ((ctx == NULL) || (mem == NULL) || (sz <= 0)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Restore certificate cache. */
        ret = CM_MemRestoreCertCache(ctx->cm, mem, sz);
    }

    return ret;
}


/* Get size of certificate cache when persisted.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  Size of certificate cache when pesisted in bytes.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_get_cert_cache_memsize");

    /* Validate parameter. */
    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Get size. */
        ret = CM_GetCertCacheMemSize(ctx->cm);
    }

    return ret;
}

#endif /* PERSIST_CERT_CACHE */

/* Unload certificates and keys that the SSL/TLS object owns.
 *
 * The WOLFSSL_CTX referenced is untouched.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_UnloadCertsKeys(WOLFSSL* ssl)
{
    int ret = 1;

    /* Validate parameter. */
    if (ssl == NULL) {
        WOLFSSL_MSG("Null function arg");
        ret = BAD_FUNC_ARG;
    }
    else {
        if (ssl->buffers.weOwnCert && !ssl->keepCert) {
            WOLFSSL_MSG("Unloading cert");
            FreeDer(&ssl->buffers.certificate);
        #ifdef KEEP_OUR_CERT
            wolfSSL_X509_free(ssl->ourCert);
            ssl->ourCert = NULL;
        #endif
            ssl->buffers.weOwnCert = 0;
        }

        if (ssl->buffers.weOwnCertChain) {
            WOLFSSL_MSG("Unloading cert chain");
            FreeDer(&ssl->buffers.certChain);
            ssl->buffers.weOwnCertChain = 0;
        }

        if (ssl->buffers.weOwnKey) {
            WOLFSSL_MSG("Unloading key");
            if (ssl->buffers.key != NULL && ssl->buffers.key->buffer != NULL)
                ForceZero(ssl->buffers.key->buffer, ssl->buffers.key->length);
            FreeDer(&ssl->buffers.key);
        #ifdef WOLFSSL_BLIND_PRIVATE_KEY
            FreeDer(&ssl->buffers.keyMask);
        #endif
            ssl->buffers.weOwnKey = 0;
    }

    #ifdef WOLFSSL_DUAL_ALG_CERTS
        if (ssl->buffers.weOwnAltKey) {
            WOLFSSL_MSG("Unloading alt key");
            if (ssl->buffers.altKey != NULL && ssl->buffers.altKey->buffer != NULL)
                ForceZero(ssl->buffers.altKey->buffer, ssl->buffers.altKey->length);
            FreeDer(&ssl->buffers.altKey);
        #ifdef WOLFSSL_BLIND_PRIVATE_KEY
            FreeDer(&ssl->buffers.altKeyMask);
        #endif
            ssl->buffers.weOwnAltKey = 0;
        }
    #endif /* WOLFSSL_DUAL_ALG_CERTS */
    }

    return ret;
}

/* Unload CAs from the certificate manager of the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx or ctx->cm is NULL.
 * @return  BAD_MUTEX_E when locking fails.
 */
int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_UnloadCAs");

    /* Validate parameter. */
    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerUnloadCAs(ctx->cm);
    }

    return ret;
}

/* Unload Intermediate CAs from the certificate manager of the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx or ctx->cm is NULL.
 * @return  BAD_MUTEX_E when locking fails.
 */
int wolfSSL_CTX_UnloadIntermediateCerts(WOLFSSL_CTX* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_UnloadIntermediateCerts");

    /* Validate parameter. */
    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Lock reference count. */
    else if ((ret = wolfSSL_RefWithMutexLock(&ctx->ref)) == 0) {
        /* Must not have another reference for this operation to be done. */
        if (ctx->ref.count > 1) {
            WOLFSSL_MSG("ctx object must have a ref count of 1 before "
                        "unloading intermediate certs");
            ret = BAD_STATE_E;
        }
        else {
            ret = wolfSSL_CertManagerUnloadIntermediateCerts(ctx->cm);
        }

        /* Unlock reference count. */
        if (wolfSSL_RefWithMutexUnlock(&ctx->ref) != 0) {
            WOLFSSL_MSG("Failed to unlock mutex!");
        }
    }

    return ret;
}


#ifdef WOLFSSL_TRUST_PEER_CERT
/* Unload trusted peers from the certificate manager of the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ctx or ctx->cm is NULL.
 * @return  BAD_MUTEX_E when locking fails.
 */
int wolfSSL_CTX_Unload_trust_peers(WOLFSSL_CTX* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_Unload_trust_peers");

    /* Validate parameter. */
    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerUnload_trust_peers(ctx->cm);
    }

    return ret;
}

#ifdef WOLFSSL_LOCAL_X509_STORE
/* Unload trusted peers from the certificate manager of the SSL/TLS object.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  BAD_MUTEX_E when locking fails.
 */
int wolfSSL_Unload_trust_peers(WOLFSSL* ssl)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_Unload_trust_peers");

    /* Validate parameter. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* Output message when certificate manager for object. */
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerUnload_trust_peers(SSL_CM(ssl));
    }

    return ret;
}
#endif /* WOLFSSL_LOCAL_X509_STORE */
#endif /* WOLFSSL_TRUST_PEER_CERT */

#ifndef WOLFSSL_NO_CA_NAMES
/* Add a CA certificate to the list of CA names.
 *
 * @param [in, out] ca_names  List of CA certificate subject names.
 * @param [in]      x509      X509 certificate.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int add_to_ca_names_list(WOLFSSL_STACK* ca_names, WOLFSSL_X509* x509)
{
    int ret = 1;
    WOLFSSL_X509_NAME *nameCopy = NULL;

    nameCopy = wolfSSL_X509_NAME_dup(wolfSSL_X509_get_subject_name(x509));
    if (nameCopy == NULL) {
        WOLFSSL_MSG("wolfSSL_X509_NAME_dup error");
        ret = 0;
    }
    else if (wolfSSL_sk_X509_NAME_push(ca_names, nameCopy) <= 0) {
        WOLFSSL_MSG("wolfSSL_sk_X509_NAME_push error");
        wolfSSL_X509_NAME_free(nameCopy);
        ret = 0;
    }

    return ret;
}

/* Add a client's CA to SSL/TLS context.
 *
 * @param [in] ctx   SSL/TLS context.
 * @param [in] x509  X509 certificate.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_add_client_CA(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_CTX_add_client_CA");

    /* Validate parameters. */
    if ((ctx == NULL) || (x509 == NULL)) {
        WOLFSSL_MSG("Bad argument");
        ret = 0;
    }
    /* Create a stack of names if not present. */
    else if (ctx->client_ca_names == NULL) {
        ctx->client_ca_names = wolfSSL_sk_X509_NAME_new(NULL);
        if (ctx->client_ca_names == NULL) {
            WOLFSSL_MSG("wolfSSL_sk_X509_NAME_new error");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Add certificate's subject name to client CA name list. */
        ret = add_to_ca_names_list(ctx->client_ca_names, x509);
    }

    return ret;
}

/* Add a client's CA to SSL/TLS object.
 *
 * @param [in] ssl   SSL/TLS object.
 * @param [in] x509  X509 certificate.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_add_client_CA(WOLFSSL* ssl, WOLFSSL_X509* x509)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_add_client_CA");

    /* Validate parameters. */
    if ((ssl == NULL) || (x509 == NULL)) {
        WOLFSSL_MSG("Bad argument");
        ret = 0;
    }
    /* Create a stack of names if not present. */
    else if (ssl->client_ca_names == NULL) {
        ssl->client_ca_names = wolfSSL_sk_X509_NAME_new(NULL);
        if (ssl->client_ca_names == NULL) {
            WOLFSSL_MSG("wolfSSL_sk_X509_NAME_new error");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Add certificate's subject name to client CA name list. */
        ret = add_to_ca_names_list(ssl->client_ca_names, x509);
    }

    return ret;
}

/* Add a CA to SSL/TLS context.
 *
 * @param [in] ctx   SSL/TLS context.
 * @param [in] x509  X509 certificate.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_CTX_add1_to_CA_list(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_CTX_add1_to_CA_list");

    /* Validate parameters. */
    if ((ctx == NULL) || (x509 == NULL)) {
        WOLFSSL_MSG("Bad argument");
        ret = 0;
    }
    /* Create a stack of names if not present. */
    else if (ctx->ca_names == NULL) {
        ctx->ca_names = wolfSSL_sk_X509_NAME_new(NULL);
        if (ctx->ca_names == NULL) {
            WOLFSSL_MSG("wolfSSL_sk_X509_NAME_new error");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Add certificate's subject name to CA name list. */
        ret = add_to_ca_names_list(ctx->ca_names, x509);
    }

    return ret;
}

/* Add a CA to SSL/TLS object.
 *
 * @param [in] ssl   SSL/TLS object.
 * @param [in] x509  X509 certificate.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_add1_to_CA_list(WOLFSSL* ssl, WOLFSSL_X509* x509)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_add1_to_CA_list");

    /* Validate parameters. */
    if ((ssl == NULL) || (x509 == NULL)) {
        WOLFSSL_MSG("Bad argument");
        ret = 0;
    }
    /* Create a stack of names if not present. */
    else if (ssl->ca_names == NULL) {
        ssl->ca_names = wolfSSL_sk_X509_NAME_new(NULL);
        if (ssl->ca_names == NULL) {
            WOLFSSL_MSG("wolfSSL_sk_X509_NAME_new error");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Add certificate's subject name to CA name list. */
        ret = add_to_ca_names_list(ssl->ca_names, x509);
    }

    return ret;
}

/* Set the client CA list into SSL/TLS context.
 *
 * @param [in] ctx    SSL/TLS context.
 * @param [in] names  List of CA subject names.
 */
void wolfSSL_CTX_set_client_CA_list(WOLFSSL_CTX* ctx,
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_client_CA_list");

    /* Validate parameters. */
    if (ctx != NULL) {
        /* Dispose of any existing list. */
        wolfSSL_sk_X509_NAME_pop_free(ctx->client_ca_names, NULL);
        /* Take ownership of names list. */
        ctx->client_ca_names = names;
    }
}

/* Set the client CA list into SSL/TLS object.
 *
 * @param [in] ssl    SSL/TLS object.
 * @param [in] names  List of CA subject names.
 */
void wolfSSL_set_client_CA_list(WOLFSSL* ssl,
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names)
{
    WOLFSSL_ENTER("wolfSSL_set_client_CA_list");

    /* Validate parameters. */
    if (ssl != NULL) {
        /* Dispose of any existing list if the object owns it. */
        if (ssl->client_ca_names != ssl->ctx->client_ca_names) {
            wolfSSL_sk_X509_NAME_pop_free(ssl->client_ca_names, NULL);
        }
        /* Take ownership of names list. */
        ssl->client_ca_names = names;
    }
}

/* Set the CA list into SSL/TLS context.
 *
 * @param [in] ctx    SSL/TLS context.
 * @param [in] names  List of CA subject names.
 */
void wolfSSL_CTX_set0_CA_list(WOLFSSL_CTX* ctx,
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set0_CA_list");

    /* Validate parameters. */
    if (ctx != NULL) {
        /* Dispose of any existing list. */
        wolfSSL_sk_X509_NAME_pop_free(ctx->ca_names, NULL);
        /* Take ownership of names list. */
        ctx->ca_names = names;
    }
}

/* Set the client CA list into SSL/TLS object.
 *
 * @param [in] ssl    SSL/TLS object.
 * @param [in] names  List of CA subject names.
 */
void wolfSSL_set0_CA_list(WOLFSSL* ssl,
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names)
{
    WOLFSSL_ENTER("wolfSSL_set0_CA_list");

    /* Validate parameters. */
    if (ssl != NULL) {
        /* Dispose of any existing list if the object owns it. */
        if (ssl->ca_names != ssl->ctx->ca_names) {
            wolfSSL_sk_X509_NAME_pop_free(ssl->ca_names, NULL);
        }
        /* Take ownership of names list. */
        ssl->ca_names = names;
    }
}

/* Get the list of client CA subject names from the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  List of CA subject names on success.
 * @return  NULL when ctx is NULL or no names set.
 */
WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_CTX_get_client_CA_list(
        const WOLFSSL_CTX *ctx)
{
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* ret;

    WOLFSSL_ENTER("wolfSSL_CTX_get_client_CA_list");

    /* Validate parameter. */
    if (ctx == NULL) {
        WOLFSSL_MSG("Bad argument passed to wolfSSL_CTX_get_client_CA_list");
        ret = NULL;
    }
    else {
        ret = ctx->client_ca_names;
    }

    return ret;
}

/* Get the list of client CA subject names from the SSL/TLS object.
 *
 * On server side: returns the CAs set via *_set_client_CA_list();
 * On client side: returns the CAs received from server -- same as
 * wolfSSL_get0_peer_CA_list().
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  List of CA subject names on success.
 * @return  NULL when ssl is NULL or no names set.
 */
WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_get_client_CA_list(const WOLFSSL* ssl)
{
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* ret;

    WOLFSSL_ENTER("wolfSSL_get_client_CA_list");

    /* Validate parameter. */
    if (ssl == NULL) {
        WOLFSSL_MSG("Bad argument passed to wolfSSL_get_client_CA_list");
        ret = NULL;
    }
    /* Client side return peer CA names. */
    else if (ssl->options.side == WOLFSSL_CLIENT_END) {
        ret = ssl->peer_ca_names;
    }
    /* Server side return client CA names. */
    else {
        ret = SSL_CLIENT_CA_NAMES(ssl);
    }

    return ret;
}

/* Get the list of CA subject names from the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  List of CA subject names on success.
 * @return  NULL when ctx is NULL or no names set.
 */
WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_CTX_get0_CA_list(
    const WOLFSSL_CTX *ctx)
{
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* ret;

    WOLFSSL_ENTER("wolfSSL_CTX_get0_CA_list");

    /* Validate parameter. */
    if (ctx == NULL) {
        WOLFSSL_MSG("Bad argument passed to wolfSSL_CTX_get0_CA_list");
        ret = NULL;
    }
    else {
        /* Return list directly. */
        ret = ctx->ca_names;
    }

    return ret;
}

/* Get the list of CA subject names from the SSL/TLS object.
 *
 * Always returns the CA's set via *_set0_CA_list.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  List of CA subject names on success.
 * @return  NULL when ssl is NULL or no names set.
 */
WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_get0_CA_list(const WOLFSSL *ssl)
{
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* ret;

    WOLFSSL_ENTER("wolfSSL_get0_CA_list");

    /* Validate parameter. */
    if (ssl == NULL) {
        WOLFSSL_MSG("Bad argument passed to wolfSSL_get0_CA_list");
        ret = NULL;
    }
    else {
        /* Return list directly from object, if available, or context. */
        ret = SSL_CA_NAMES(ssl);
    }

    return ret;
}

/* Get the list of peer CA subject names from the SSL/TLS object.
 *
 * Always returns the CA's received from the peer.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  List of CA subject names on success.
 * @return  NULL when ssl is NULL or no names set.
 */
WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_get0_peer_CA_list(const WOLFSSL* ssl)
{
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* ret;

    WOLFSSL_ENTER("wolfSSL_get0_peer_CA_list");

    /* Validate parameter. */
    if (ssl == NULL) {
        WOLFSSL_MSG("Bad argument passed to wolfSSL_get0_peer_CA_list");
        ret = NULL;
    }
    else {
        /* Return list directly from object. */
        ret = ssl->peer_ca_names;
    }

    return ret;
}

#ifndef NO_BIO
/* Load the client CA subject names from file.
 *
 * @param [in] fname  Name of file containing client CA certificates.
 * @return  A list of certificate names on success.
 * @return  NULL on error.
 */
WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_load_client_CA_file(const char* fname)
{
    /* The webserver build is using this to load a CA into the server
     * for client authentication as an option. Have this return NULL in
     * that case. If OPENSSL_EXTRA is enabled, go ahead and include
     * the function. */
#ifdef OPENSSL_EXTRA
    WOLFSSL_STACK *list = NULL;
    WOLFSSL_BIO* bio = NULL;
    WOLFSSL_X509 *cert = NULL;
    int err = 0;
    unsigned long error;

    WOLFSSL_ENTER("wolfSSL_load_client_CA_file");

    /* Create a file BIO to read. */
    bio = wolfSSL_BIO_new_file(fname, "rb");
    if (bio == NULL) {
        WOLFSSL_MSG("wolfSSL_BIO_new_file error");
        err = 1;
    }

    if (!err) {
        /* Create an empty list of certificate names - default compare cb. */
        list = wolfSSL_sk_X509_NAME_new(NULL);
        if (list == NULL) {
            WOLFSSL_MSG("wolfSSL_sk_X509_NAME_new error");
            err = 1;
        }
    }

    /* Read each certificate in the chain out of the file. */
    while (!err && wolfSSL_PEM_read_bio_X509(bio, &cert, NULL, NULL) != NULL) {
        WOLFSSL_X509_NAME *nameCopy;

        /* Need a persistent copy of the subject name. */
        nameCopy = wolfSSL_X509_NAME_dup(wolfSSL_X509_get_subject_name(cert));
        if (nameCopy == NULL) {
            WOLFSSL_MSG("wolfSSL_X509_NAME_dup error");
            err = 1;
        }
        else {
            /* Original certificate will be freed - clear reference to it. */
            nameCopy->x509 = NULL;

            if (wolfSSL_sk_X509_NAME_push(list, nameCopy) <= 0) {
                WOLFSSL_MSG("wolfSSL_sk_X509_NAME_push error");
                /* Name not stored - free now as only place needing to. */
                wolfSSL_X509_NAME_free(nameCopy);
                err = 1;
            }
        }

        /* Dispose of certificate read. */
        wolfSSL_X509_free(cert);
        cert = NULL;
    }

    /* Clear any error due to no more certificates. */
    CLEAR_ASN_NO_PEM_HEADER_ERROR(error);

    if (err) {
        /* Error occurred so return NULL. */
        wolfSSL_sk_X509_NAME_pop_free(list, NULL);
        list = NULL;
    }
    wolfSSL_BIO_free(bio);
    return list;
#else
    (void)fname;
    return NULL;
#endif
}
#endif /* !NO_BIO */
#endif /* WOLFSSL_NO_CA_NAMES */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Get the certificate store of the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  X509 certificate store on success.
 * @return  NULL when ctx is NULL.
 */
WOLFSSL_X509_STORE* wolfSSL_CTX_get_cert_store(const WOLFSSL_CTX* ctx)
{
    WOLFSSL_X509_STORE* ret;

    /* Validate parameter. */
    if (ctx == NULL) {
        ret = NULL;
    }
    /* Use pointer to external store if set. */
    else if (ctx->x509_store_pt != NULL) {
        ret = ctx->x509_store_pt;
    }
    else {
        /* Return reference to store that is part of the context. */
        ret = (WOLFSSL_X509_STORE*)&ctx->x509_store;
    }

    return ret;
}

/* Set the certificate store of the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  X509 certificate store on success.
 * @return  NULL when ctx is NULL.
 */
void wolfSSL_CTX_set_cert_store(WOLFSSL_CTX* ctx, WOLFSSL_X509_STORE* str)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_cert_store");

    /* Validate parameters. */
    if ((ctx == NULL) || (str == NULL) || (ctx->cm == str->cm)) {
        WOLFSSL_MSG("Invalid parameters");
    }
    else if (wolfSSL_CertManager_up_ref(str->cm) != 1) {
        WOLFSSL_MSG("wolfSSL_CertManager_up_ref error");
    }
    else {
        /* Free any cert manager. */
        wolfSSL_CertManagerFree(ctx->cm);
        /* Free any external store. */
        wolfSSL_X509_STORE_free(ctx->x509_store_pt);
        /* Set the certificate manager into context. */
        ctx->cm               = str->cm;
        ctx->x509_store.cm    = str->cm;
        ctx->x509_store.cache = str->cache;
        /* Take ownership of store and free it with context free. */
        ctx->x509_store_pt    = str;
        /* Context has ownership and free it with context free. */
        ctx->cm->x509_store_p = ctx->x509_store_pt;
    }
}

#ifdef OPENSSL_ALL
/* Set certificate store into SSL/TLS context but don't take ownership.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] str  Certificate store.
 * @return  1 on success.
 * @return  0 when ctx or str is NULL or on other error.
 */
int wolfSSL_CTX_set1_verify_cert_store(WOLFSSL_CTX* ctx,
    WOLFSSL_X509_STORE* str)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_set1_verify_cert_store");

    /* Validate parameters. */
    if ((ctx == NULL) || (str == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        ret = 0;
    }
    /* Nothing to do when store being set is the same as existing in context. */
    else if (str == CTX_STORE(ctx)) {
        ret = 1;
    }
    /* Increase ref so we can store pointer and free it with context free. */
    else if (wolfSSL_X509_STORE_up_ref(str) != 1) {
        WOLFSSL_MSG("wolfSSL_X509_STORE_up_ref error");
        ret = 0;
    }
    else {
        /* Free any external store. */
        wolfSSL_X509_STORE_free(ctx->x509_store_pt);
        /* Ref count increased - store pointer and free with context free. */
        ctx->x509_store_pt = str;
        ret = 1;
    }

    return ret;
}
#endif


/* Set certificate store into SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] str  Certificate store.
 * @param [in] ref  Take a reference to passed in certificate store.
 * @return  1 on success.
 * @return  0 when ssl or str is NULL or on other error.
 */
static int wolfssl_set_verify_cert_store(WOLFSSL *ssl, WOLFSSL_X509_STORE* str,
    int ref)
{
    int ret;

    WOLFSSL_ENTER("wolfssl_set_verify_cert_store");

    /* Validate parameters. */
    if ((ssl == NULL) || (str == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        ret = 0;
    }
    /* Nothing to do when store being set is the same as existing in object. */
    else if (str == SSL_STORE(ssl)) {
        ret = 1;
    }
    else if (ref && (wolfSSL_X509_STORE_up_ref(str) != 1)) {
        WOLFSSL_MSG("wolfSSL_X509_STORE_up_ref error");
        ret = 0;
    }
    else {
        /* Free any external store. */
        wolfSSL_X509_STORE_free(ssl->x509_store_pt);
        if (str == ssl->ctx->x509_store_pt) {
            /* Setting ctx store - just revert to using that instead. */
            ssl->x509_store_pt = NULL;
        }
        else {
            /* Ref count increased - store pointer and free with object free. */
            ssl->x509_store_pt = str;
        }
        ret = 1;
    }

    return ret;
}

/* Set certificate store into SSL/TLS object and take ownership.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] str  Certificate store.
 * @return  1 on success.
 * @return  0 when ssl or str is NULL or on other error.
 */
int wolfSSL_set0_verify_cert_store(WOLFSSL *ssl, WOLFSSL_X509_STORE* str)
{
    WOLFSSL_ENTER("wolfSSL_set0_verify_cert_store");

    return wolfssl_set_verify_cert_store(ssl, str, 0);
}

/* Set certificate store into SSL/TLS object but don't take ownership.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] str  Certificate store.
 * @return  1 on success.
 * @return  0 when ssl or str is NULL or on other error.
 */
int wolfSSL_set1_verify_cert_store(WOLFSSL *ssl, WOLFSSL_X509_STORE* str)
{
    WOLFSSL_ENTER("wolfSSL_set1_verify_cert_store");

    return wolfssl_set_verify_cert_store(ssl, str, 1);
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

/* OPENSSL_EXTRA is needed for wolfSSL_X509_d21 function
   KEEP_OUR_CERT is to ensure ability to return ssl certificate */
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    defined(KEEP_OUR_CERT)
/* Get the certificate in the SSL/TLS context.
 *
 * @param [in] ctx  SSL/TLS context.
 * @return  Certificate being sent to peer.
 * @return  NULL when ctx is NULL, no certificate set or on other error.
 */
WOLFSSL_X509* wolfSSL_CTX_get0_certificate(WOLFSSL_CTX* ctx)
{
    WOLFSSL_X509* ret = NULL;

    /* Validate parameters. */
    if (ctx == NULL) {
        WOLFSSL_MSG("Invalid parameter");
    }
    else {
        /* Check if we already have a certificate allocated. */
        if (ctx->ourCert == NULL) {
            /* Check if there is a raw certificate. */
            if (ctx->certificate == NULL) {
                WOLFSSL_MSG("Ctx Certificate buffer not set!");
            }
        #ifndef WOLFSSL_X509_STORE_CERTS
            else {
                /* Create a certificate object from raw data. */
                ctx->ourCert = wolfSSL_X509_d2i_ex(NULL,
                    ctx->certificate->buffer, (int)ctx->certificate->length,
                    ctx->heap);
                ctx->ownOurCert = 1;
            }
        #endif
        }
        /* Return certificate cached against SSL/TLS context. */
        ret = ctx->ourCert;
    }

    return ret;
}

/* Get the certificate in the SSL/TLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Certificate being sent to peer.
 * @return  NULL when ssl is NULL, no certificate set or on other error.
 */
WOLFSSL_X509* wolfSSL_get_certificate(WOLFSSL* ssl)
{
    WOLFSSL_X509* ret = NULL;

    /* Validate parameters. */
    if (ssl == NULL) {
        WOLFSSL_MSG("Invalid parameter");
    }
    /* Use certificate in SSL/TLS object if we own it. */
    else if (ssl->buffers.weOwnCert) {
        /* Check if we already have a certificate allocated. */
        if (ssl->ourCert == NULL) {
            /* Check if ctx has ourCert set - if so, use it instead of creating
             * a new X509. This maintains pointer compatibility with
             * applications (like nginx OCSP stapling) that use the X509 pointer
             * from SSL_CTX_use_certificate as a lookup key. */
            if (ssl->ctx != NULL && ssl->ctx->ourCert != NULL) {
                /* Compare cert buffers to make sure they are the same */
                if (ssl->buffers.certificate == NULL ||
                    ssl->buffers.certificate->buffer == NULL ||
                   (ssl->buffers.certificate->length ==
                    ssl->ctx->certificate->length &&
                    XMEMCMP(ssl->buffers.certificate->buffer,
                             ssl->ctx->certificate->buffer,
                             ssl->buffers.certificate->length) == 0)) {
                    return ssl->ctx->ourCert;
                }
            }
            /* We own certificate so this should never happen. */
            if (ssl->buffers.certificate == NULL) {
                WOLFSSL_MSG("Certificate buffer not set!");
            }
        #ifndef WOLFSSL_X509_STORE_CERTS
            else {
                /* Create a certificate object from raw data. */
                ssl->ourCert = wolfSSL_X509_d2i_ex(NULL,
                    ssl->buffers.certificate->buffer,
                    (int)ssl->buffers.certificate->length, ssl->heap);
            }
        #endif
        }
        /* Return certificate cached against SSL/TLS object. */
        ret = ssl->ourCert;
    }
    else {
        /* Use any certificate in SSL/TLS context instead. */
        ret = wolfSSL_CTX_get0_certificate(ssl->ctx);
    }

    return ret;
}
#endif /* (OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL) && KEEP_OUR_CERT */

#endif /* !NO_CERTS */

#endif /* !WOLFSSL_SSL_API_CERT_INCLUDED */
