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
    /* Mutual authentication is a server-side only setting. */
    if (ctx->method->side != WOLFSSL_SERVER_END)
        return SIDE_ERROR;

    ctx->mutualAuth = (byte)req;

    return 0;
}

/* Set whether mutual authentication is required for the connection.
 * Server side only.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      req  1 to indicate required and 0 when not.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  SIDE_ERROR when not a server
 */
int wolfSSL_mutual_auth(WOLFSSL* ssl, int req)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;
    /* Mutual authentication is a server-side only setting. */
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

    /* The certificate manager is owned by the context. */
    if (ctx != NULL)
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

    /* Reject out-of-range depths; valid range is 0 to MAX_CHAIN_DEPTH. */
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
        /* A configurable depth is only tracked with the OpenSSL extra APIs;
         * otherwise the fixed maximum chain depth applies. */
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
        /* A configurable depth is only tracked with the OpenSSL extra APIs;
         * otherwise the fixed maximum chain depth applies. */
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
    /* Check the array is unique. */
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
        /* A side value of 1 records these as the client certificate types. */
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
        /* A side value of 0 records these as the server certificate types. */
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
        /* A side value of 1 records these as the client certificate types. */
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
        /* A side value of 0 records these as the server certificate types. */
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

#ifndef NO_SHA256
/* Store the SHA-256 digest of a DER SubjectPublicKeyInfo as an expected Raw
 * Public Key (RFC 7250) for out-of-band trust.
 *
 * @param [in] cfg     RPK configuration to add the pin to.
 * @param [in] spki    DER-encoded SubjectPublicKeyInfo.
 * @param [in] spkiSz  Length of spki in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when cfg or spki is NULL, or spkiSz is 0.
 * @return  BUFFER_E when no more pins can be stored.
 * @return  negative hashing error on failure.
 */
static int rpk_add_expected(RpkConfig* cfg, const unsigned char* spki,
    unsigned int spkiSz)
{
    int ret;

    if ((cfg == NULL) || (spki == NULL) || (spkiSz == 0)) {
        return BAD_FUNC_ARG;
    }
    if (cfg->expectedRpkCnt >= WOLFSSL_MAX_RPK_PINS) {
        return BUFFER_E;
    }

    ret = wc_Sha256Hash(spki, spkiSz, cfg->expectedRpk[cfg->expectedRpkCnt]);
    if (ret == 0) {
        cfg->expectedRpkCnt++;
    }
    return ret;
}

/* Pin an expected peer Raw Public Key on the SSL/TLS CTX object.
 *
 * @param [in] ctx     SSL/TLS CTX object.
 * @param [in] spki    DER-encoded SubjectPublicKeyInfo the peer will present.
 * @param [in] spkiSz  Length of spki in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx or spki is NULL, or spkiSz is 0.
 * @return  BUFFER_E when the pin table is full (WOLFSSL_MAX_RPK_PINS reached).
 * @return  Other negative error code on hashing failure.
 */
int wolfSSL_CTX_set_expected_rpk(WOLFSSL_CTX* ctx, const unsigned char* spki,
    unsigned int spkiSz)
{
    int ret;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = rpk_add_expected(&ctx->rpkConfig, spki, spkiSz);
    return (ret == 0) ? WOLFSSL_SUCCESS : ret;
}

/* Pin an expected peer Raw Public Key on the SSL/TLS object.
 *
 * @param [in] ssl     SSL/TLS object.
 * @param [in] spki    DER-encoded SubjectPublicKeyInfo the peer will present.
 * @param [in] spkiSz  Length of spki in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl or spki is NULL, or spkiSz is 0.
 * @return  BUFFER_E when the pin table is full (WOLFSSL_MAX_RPK_PINS reached).
 * @return  Other negative error code on hashing failure.
 */
int wolfSSL_set_expected_rpk(WOLFSSL* ssl, const unsigned char* spki,
    unsigned int spkiSz)
{
    int ret;

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = rpk_add_expected(&ssl->options.rpkConfig, spki, spkiSz);
    return (ret == 0) ? WOLFSSL_SUCCESS : ret;
}

/* Remove all pinned expected peer Raw Public Keys from the SSL/TLS CTX object,
 * so the table can be repopulated (e.g. across a peer key rotation).
 *
 * @param [in] ctx  SSL/TLS CTX object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_clear_expected_rpk(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    ctx->rpkConfig.expectedRpkCnt = 0;
    return WOLFSSL_SUCCESS;
}

/* Remove all pinned expected peer Raw Public Keys from the SSL/TLS object, so
 * the table can be repopulated (e.g. across a peer key rotation).
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_clear_expected_rpk(WOLFSSL* ssl)
{
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    ssl->options.rpkConfig.expectedRpkCnt = 0;
    return WOLFSSL_SUCCESS;
}
#endif /* !NO_SHA256 */
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
 * WOLFSSL_VERIFY_CLIENT_ONCE is accepted and deliberately ignored - it has no
 * corresponding option here, is not stored anywhere, and therefore cannot be
 * read back by wolfSSL_[CTX_]get_verify_mode(). See the note on the enumerator
 * in wolfssl/ssl.h.
 *
 * Note that WOLFSSL_VERIFY_NONE is matched by equality, not as a bit: a mode
 * of (WOLFSSL_VERIFY_NONE | WOLFSSL_VERIFY_PEER) verifies the peer.
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
WOLFSSL_ABI
void wolfSSL_CTX_set_verify(WOLFSSL_CTX* ctx, int mode,
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
 * @param [in, out] ssl              SSL/TLS object.
 * @param [in]      mode             Verification mode options.
 * @param [in]      verify_callback  Verification callback.
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
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      v    Verification result.
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
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      ctx  User context for verify callback.
 */
void wolfSSL_SetCertCbCtx(WOLFSSL* ssl, void* ctx)
{
    WOLFSSL_ENTER("wolfSSL_SetCertCbCtx");

    /* Validate parameters. */
    if (ssl != NULL) {
        ssl->verifyCbCtx = ctx;
    }
}



/* Set the callback called when a CA is added to the cache.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @param [in]      cb   Callback to call. NULL to clear.
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
 * @param [in, out] ssl  SSL/TLS object.
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
        if ((ssl != NULL) && (!IsAtLeastTLSv1_3(ssl->version))) {
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
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      val  Whether to allow post handshake authentication.
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
 * @param [in] ctx  SSL/TLS context.
 * @param [in] mem  Memory with certificate cache.
 * @param [in] sz   Size of certificate cache in bytes
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
 * @param [in, out] ssl  SSL/TLS object.
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
        if (ssl->buffers.weOwnCert && (!ssl->keepCert)) {
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
            if ((ssl->buffers.key != NULL) &&
                (ssl->buffers.key->buffer != NULL)) {
                ForceZero(ssl->buffers.key->buffer, ssl->buffers.key->length);
            }
            FreeDer(&ssl->buffers.key);
            #ifdef WOLFSSL_BLIND_PRIVATE_KEY
            FreeDer(&ssl->buffers.keyMask);
            #endif
            ssl->buffers.weOwnKey = 0;
        }

        #ifdef WOLFSSL_DUAL_ALG_CERTS
        if (ssl->buffers.weOwnAltKey) {
            WOLFSSL_MSG("Unloading alt key");
            if ((ssl->buffers.altKey != NULL) &&
                    (ssl->buffers.altKey->buffer != NULL)) {
                ForceZero(ssl->buffers.altKey->buffer,
                          ssl->buffers.altKey->length);
            }
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
 * @return  BAD_STATE_E when another reference to the context is held.
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
 * @param [in, out] ssl  SSL/TLS object.
 * @return  1 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  BAD_MUTEX_E when locking fails.
 */
int wolfSSL_Unload_trust_peers(WOLFSSL* ssl)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_Unload_trust_peers");

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

    /* The list owns its names, so push a copy of the subject name. */
    nameCopy = wolfSSL_X509_NAME_dup(wolfSSL_X509_get_subject_name(x509));
    if (nameCopy == NULL) {
        WOLFSSL_MSG("wolfSSL_X509_NAME_dup error");
        ret = 0;
    }
    /* On push failure the copy is not owned by the list - free it here. */
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
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      x509  X509 certificate.
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
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      x509  X509 certificate.
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
    while ((!err) && (wolfSSL_PEM_read_bio_X509(bio, &cert, NULL, NULL) != NULL)) {
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
 * The store is not taken when it shares the context's certificate manager.
 *
 * Ownership: the caller's reference to the store is taken over - no reference
 * is added here, and the context releases it on free. A caller that means to
 * keep using the store must take its own reference first with
 * wolfSSL_X509_STORE_up_ref(). A reference is added to the store's
 * certificate manager, which the context then uses as its own.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @param [in]      str  X509 certificate store to use.
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

        #ifdef OPENSSL_EXTRA
        /* Non-self-signed certs (intermediates) added via
         * X509_STORE_add_cert only go into store->certs, not the
         * CertManager. Push them into the CM now so that all
         * verification paths can find them. */
        if (X509StorePushCertsToCM(str) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_CTX_set_cert_store: failed to push some "
                        "certs to CertManager");
        }
        #endif
    }
}

#ifdef OPENSSL_ALL
/* Set certificate store into SSL/TLS context but don't take ownership.
 *
 * A NULL store is refused, which is a deviation from OpenSSL, where
 * SSL_CTX_set1_verify_cert_store(ctx, NULL) returns 1 and releases the verify
 * store so the context falls back to its own. OpenSSL keeps two stores on a
 * context, the one set by SSL_CTX_set_cert_store() and the verify store this
 * call sets; both live in ctx->x509_store_pt here, so releasing it on NULL
 * would also throw away the store handed to wolfSSL_CTX_set_cert_store() and
 * drop the context back to its own, which is not set up for certificate
 * lookup by issuer. Until the two are held separately the request cannot be
 * honoured, and refusing it is what keeps that visible - returning success
 * without clearing would leave the caller verifying against the store it
 * asked to be rid of.
 *
 * Note the asymmetry with the object-level setters:
 * wolfSSL_set0_verify_cert_store() and wolfSSL_set1_verify_cert_store() do
 * clear on NULL, because an object reverts to the context's store rather than
 * having a second store of its own to throw away.
 *
 * @param [in] ctx  SSL/TLS context.
 * @param [in] str  Certificate store. NULL is refused.
 * @return  1 on success.
 * @return  0 when ctx or str is NULL, or on other error.
 */
int wolfSSL_CTX_set1_verify_cert_store(WOLFSSL_CTX* ctx,
    WOLFSSL_X509_STORE* str)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_set1_verify_cert_store");

    /* Validate parameters. A NULL store is refused rather than accepted and
     * ignored. OpenSSL keeps two stores on a context - the one set by
     * SSL_CTX_set_cert_store() and the verify store this call sets - and
     * clearing the verify store leaves the other alone. Both live in
     * ctx->x509_store_pt here, so releasing it on NULL would throw away the
     * store handed to wolfSSL_CTX_set_cert_store() and drop the context back
     * to its own, which is not set up for certificate lookup by issuer.
     * Reporting failure keeps that unsupported request visible: returning
     * success without clearing would leave the caller verifying against the
     * store it asked to be rid of, with no way to tell. */
    if ((ctx == NULL) || (str == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        ret = 0;
    }
    /* Nothing to do when store being set is the same as existing in context. */
    else if (str == CTX_STORE(ctx)) {
        ret = 1;
    }
    /* Take a reference so the pointer can be stored and released with the
     * context. A store that is part of another object has none to take - the
     * pointer is then kept without anything protecting it. */
    else if (wolfSSL_X509_STORE_up_ref(str) != 1) {
        WOLFSSL_MSG("wolfSSL_X509_STORE_up_ref error");
        ret = 0;
    }
    else {
        /* Free any external store. */
        wolfSSL_X509_STORE_free(ctx->x509_store_pt);
        /* Ref count increased - store pointer and free with context free. */
        ctx->x509_store_pt = str;
        /* As above: the store just released may have been the one this
         * manager names, which leaves the manager with no store for the
         * lookup by issuer. Unlike wolfSSL_CTX_set_cert_store(), this setter
         * does not adopt the new store's manager - str carries its own, and
         * that is the one verification resolves through, so pairing this
         * manager with str would cross-link two independent managers. The
         * context's own store is used instead: what the manager needs is a
         * store that stays valid for as long as it does, not the one
         * currently in use. */
        if ((ctx->cm != NULL) && (ctx->cm->x509_store_p == NULL)) {
            ctx->cm->x509_store_p = &ctx->x509_store;
        }
        ret = 1;
    }

    return ret;
}
#endif


/* Set the certificate store used for verification by the SSL/TLS object.
 *
 * Ownership: with ref set, a reference is taken here (set1 semantics);
 * without it the caller's reference is handed over (set0 semantics). With
 * ref set the accounting always nets to zero - the reference taken is kept
 * with the stored pointer, or released again when no pointer is kept.
 *
 * A set0 caller's reference is consumed by being kept, except on the two
 * paths that keep no pointer and cannot safely release it either: being
 * handed the store the object already uses, and being handed the context's
 * store while the object holds one of its own. Both leak that reference by
 * design - see the comments on those branches; releasing it would free a
 * reference a misusing caller never took.
 *
 * A store that is part of another object has no reference count to take, so
 * nothing keeps it alive for as long as the pointer is held here - see
 * wolfSSL_X509_STORE_up_ref(). Storing one that belongs to a different
 * object outlives its owner only by luck.
 *
 * A set0 caller must therefore own a reference. Handing over a borrowed
 * pointer, such as one straight from wolfSSL_CTX_get_cert_store(), releases
 * a reference the caller never took and can destroy a store still in use.
 *
 * The object uses the context's store by keeping no pointer of its own, so
 * that is how both a NULL store, which clears, and being handed the store the
 * context already uses are done. Clearing on NULL rather than rejecting it
 * matches OpenSSL.
 *
 * "The store the context already uses" is what CTX_STORE() resolves to, which
 * is the context's own store when no other has been set on it. So handing
 * over wolfSSL_CTX_get_cert_store() of such a context makes the object follow
 * the context rather than pinning that store: a later
 * wolfSSL_CTX_set1_verify_cert_store() then changes what the object verifies
 * against. OpenSSL's SSL_set1_verify_cert_store() pins instead, and so did
 * this before the context's own store was included in the comparison.
 * Following is the safer of the two here, because a store that is part of
 * another object has no reference count and pinning it stores a pointer with
 * nothing keeping it alive.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      str  X509 certificate store to use. NULL to clear.
 * @param [in]      ref  Whether to take a reference to the store.
 * @return  1 on success.
 * @return  0 when ssl is NULL, or the reference cannot be taken.
 */
static int wolfssl_set_verify_cert_store(WOLFSSL *ssl, WOLFSSL_X509_STORE* str,
    int ref)
{
    int ret;

    WOLFSSL_ENTER("wolfssl_set_verify_cert_store");

    /* Validate parameters. */
    if (ssl == NULL) {
        WOLFSSL_MSG("Bad parameter");
        ret = 0;
    }
    /* Already the store this object uses - its own, or the context's when it
     * has none of its own: leave every reference where it is, as the original
     * code did. Consuming one here would release a reference the object or
     * the context still relies on when a set0 caller passed a pointer it did
     * not own, which is a use-after-free for the object's store and a second
     * free at wolfSSL_CTX_free() for the context's. A leaked reference is the
     * safer of the two outcomes for an entry point applications reach through
     * the OpenSSL compatibility layer. */
    else if (str == SSL_STORE(ssl)) {
        ret = 1;
    }
    /* Take the reference to become responsible for before releasing the one
     * the object holds below. The two name different stores - the store the
     * object already uses is caught by the early exit above. */
    else if (ref && (str != NULL) && (wolfSSL_X509_STORE_up_ref(str) != 1)) {
        WOLFSSL_MSG("wolfSSL_X509_STORE_up_ref error");
        ret = 0;
    }
    else {
        /* The object uses the context's store by keeping no pointer, so that
         * is what being handed that store means here. A NULL store, which
         * clears, is kept as it is and so keeps no pointer either. */
        WOLFSSL_X509_STORE* keep = (str == CTX_STORE(ssl->ctx)) ? NULL : str;

        /* Release the store held, if any, and take on the new one. The
         * reference this call is responsible for - taken above for set1,
         * handed over for set0 - is consumed by being kept. */
        wolfSSL_X509_STORE_free(ssl->x509_store_pt);
        ssl->x509_store_pt = keep;
        if ((keep == NULL) && ref) {
            /* Nothing kept the reference taken above, so give it back. Only
             * set1 gets here: a set0 caller's reference must be left alone,
             * as the store it named is the context's and releasing it would
             * leave ctx->x509_store_pt pointing at memory freed a second
             * time by wolfSSL_CTX_free(). */
            wolfSSL_X509_STORE_free(str);
        }
        ret = 1;
    }

    return ret;
}

/* Set certificate store into SSL/TLS object and take ownership.
 *
 * The caller must own a reference to the store - it is consumed here. A NULL
 * store clears any store previously set on the object. *
 * Passing the store the context is currently using - what
 * wolfSSL_CTX_get_cert_store() returns - makes the object track the context
 * instead of pinning that store, so a later
 * wolfSSL_CTX_set1_verify_cert_store() changes what this object verifies
 * against. OpenSSL's equivalent pins the store. See
 * wolfssl_set_verify_cert_store() for why following is preferred here.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in] str  Certificate store. NULL to clear.
 * @return  1 on success.
 * @return  0 when ssl is NULL or on other error.
 */
int wolfSSL_set0_verify_cert_store(WOLFSSL *ssl, WOLFSSL_X509_STORE* str)
{
    WOLFSSL_ENTER("wolfSSL_set0_verify_cert_store");

    return wolfssl_set_verify_cert_store(ssl, str, 0);
}

/* Set certificate store into SSL/TLS object but don't take ownership.
 *
 * A NULL store clears any store previously set on the object. *
 * Passing the store the context is currently using - what
 * wolfSSL_CTX_get_cert_store() returns - makes the object track the context
 * instead of pinning that store, so a later
 * wolfSSL_CTX_set1_verify_cert_store() changes what this object verifies
 * against. OpenSSL's equivalent pins the store. See
 * wolfssl_set_verify_cert_store() for why following is preferred here.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in] str  Certificate store. NULL to clear.
 * @return  1 on success.
 * @return  0 when ssl is NULL or on other error.
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
 * @param [in, out] ssl  SSL/TLS object.
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
            if ((ssl->ctx != NULL) && (ssl->ctx->ourCert != NULL)) {
                /* Compare cert buffers to make sure they are the same */
                if ((ssl->buffers.certificate == NULL) ||
                    (ssl->buffers.certificate->buffer == NULL) ||
                   ((ssl->buffers.certificate->length ==
                     ssl->ctx->certificate->length) &&
                    (XMEMCMP(ssl->buffers.certificate->buffer,
                             ssl->ctx->certificate->buffer,
                             ssl->buffers.certificate->length) == 0))) {
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

#ifndef WOLFCRYPT_ONLY

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
/* Get the index at which the object is stored in an X509 store context's
 * external data.
 *
 * @return  Index of the SSL/TLS object (0).
 */
int wolfSSL_get_ex_data_X509_STORE_CTX_idx(void)
{
    WOLFSSL_ENTER("wolfSSL_get_ex_data_X509_STORE_CTX_idx");

    /* store SSL at index 0 */
    return 0;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */


#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL) || \
    defined(OPENSSL_ALL)
/* Get the result of peer certificate verification.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Verification result code on success.
 * @return  WOLFSSL_X509_V_ERR_APPLICATION_VERIFICATION when ssl is NULL.
 */
long wolfSSL_get_verify_result(const WOLFSSL *ssl)
{
    long ret;

    if (ssl == NULL) {
        /* Return a non-zero error so the OpenSSL-idiomatic
         * "!= X509_V_OK" check does not mistake a NULL ssl for a
         * successful verification (X509_V_OK is 0). */
        ret = WOLFSSL_X509_V_ERR_APPLICATION_VERIFICATION;
    }
    else {
        /* Result of verifying the peer's certificate chain. */
        ret = (long)ssl->peerVerifyRet;
    }

    return ret;
}
#endif


#if defined(OPENSSL_EXTRA) && defined(KEEP_PEER_CERT) && \
    defined(HAVE_EX_DATA) && !defined(NO_FILESYSTEM)
/* Compare the peer's certificate against a PEM certificate file.
 *
 * @param [in] ssl    SSL/TLS object.
 * @param [in] fname  Path to a PEM certificate file.
 * @return  0 when the certificates match.
 * @return  WOLFSSL_FATAL_ERROR when arguments are NULL or they do not match.
 * @return  WOLFSSL_BAD_FILE when the file cannot be read.
 */
int wolfSSL_cmp_peer_cert_to_file(WOLFSSL* ssl, const char *fname)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_cmp_peer_cert_to_file");

    if ((ssl == NULL) || (fname == NULL)) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    else {
        #ifdef WOLFSSL_SMALL_STACK
        byte staticBuffer[1]; /* force heap usage */
        #else
        byte staticBuffer[FILE_BUFFER_SIZE];
        #endif
        byte* myBuf = staticBuffer;
        XFILE file;
        long sz = 0;
        void* heap = ssl->ctx->heap;
        WOLFSSL_X509* peer_cert = &ssl->peerCert;
        DerBuffer* fileDer = NULL;

        /* Open the file and determine its size. From here, ret == 0
         * indicates processing is still on track. */
        file = XFOPEN(fname, "rb");
        ret = wolfssl_file_len(file, &sz);
        /* Use a heap buffer when the file is bigger than the stack buffer. */
        if ((ret == 0) && (sz > (long)sizeof(staticBuffer))) {
            WOLFSSL_MSG("Getting dynamic buffer");
            myBuf = (byte*)XMALLOC((size_t)sz, heap, DYNAMIC_TYPE_FILE);
            if (myBuf == NULL) {
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
        /* Read the whole file into the buffer. */
        if ((ret == 0) && (XFREAD(myBuf, 1, (size_t)sz, file) != (size_t)sz)) {
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* Convert the PEM file contents to DER. */
        if ((ret == 0) && (PemToDer(myBuf, sz, CERT_TYPE, &fileDer, heap, NULL,
                                    NULL) != 0)) {
            ret = WOLFSSL_FATAL_ERROR;
        }
        /* Peer certificate matches when the DER lengths and bytes are equal. */
        if ((ret == 0) && ((fileDer->length == 0) ||
                (fileDer->length != peer_cert->derCert->length) ||
                (XMEMCMP(peer_cert->derCert->buffer, fileDer->buffer,
                         fileDer->length) != 0))) {
            ret = WOLFSSL_FATAL_ERROR;
        }

        /* Dispose of the DER, any heap buffer and close the file. */
        FreeDer(&fileDer);
        if (myBuf != staticBuffer) {
            XFREE(myBuf, heap, DYNAMIC_TYPE_FILE);
        }
        if (file != XBADFILE) {
            XFCLOSE(file);
        }
    }

    return ret;
}
#endif


#ifdef WOLFSSL_ALT_CERT_CHAINS
/* Determine whether the peer was verified using an alternate cert chain.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when an alternate certificate chain was used.
 * @return  0 otherwise, or when ssl is NULL.
 */
int wolfSSL_is_peer_alt_cert_chain(const WOLFSSL* ssl)
{
    return (ssl != NULL) && ssl->options.usingAltCertChain;
}
#endif /* WOLFSSL_ALT_CERT_CHAINS */


#ifdef SESSION_CERTS

#ifdef WOLFSSL_ALT_CERT_CHAINS
/* Get the peer's alternate certificate chain.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Alternate certificate chain on success.
 * @return  NULL when ssl is NULL.
 */
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_alt_chain(WOLFSSL* ssl)
{
    WOLFSSL_X509_CHAIN* chain = NULL;

    WOLFSSL_ENTER("wolfSSL_get_peer_alt_chain");

    if (ssl != NULL) {
        /* The alternate chain is held within the session. */
        chain = &ssl->session->altChain;
    }

    return chain;
}
#endif /* WOLFSSL_ALT_CERT_CHAINS */


/* Get the peer's certificate chain.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Certificate chain on success.
 * @return  NULL when ssl is NULL.
 */
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl)
{
    WOLFSSL_X509_CHAIN* chain = NULL;

    WOLFSSL_ENTER("wolfSSL_get_peer_chain");

    if (ssl != NULL) {
        /* The peer chain is held within the session. */
        chain = &ssl->session->chain;
    }

    return chain;
}


/* Get the number of certificates in a certificate chain.
 *
 * @param [in] chain  Certificate chain object.
 * @return  Number of certificates on success.
 * @return  0 when chain is NULL.
 */
int wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain)
{
    int count = 0;

    WOLFSSL_ENTER("wolfSSL_get_chain_count");

    if (chain != NULL) {
        /* Number of certificates captured in the chain. */
        count = chain->count;
    }

    return count;
}


/* Get the length, in bytes, of the DER certificate at an index in a chain.
 *
 * @param [in] chain  Certificate chain object.
 * @param [in] idx    Index of the certificate in the chain.
 * @return  Length of the DER certificate in bytes on success.
 * @return  0 when chain is NULL or idx is out of range.
 */
int wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN* chain, int idx)
{
    int length = 0;

    WOLFSSL_ENTER("wolfSSL_get_chain_length");

    if ((chain != NULL) && (idx >= 0) && (idx < chain->count)) {
        /* DER length of the certificate stored at the given index. */
        length = chain->certs[idx].length;
    }

    return length;
}


/* Get the DER certificate at an index in a certificate chain.
 *
 * @param [in] chain  Certificate chain object.
 * @param [in] idx    Index of the certificate in the chain.
 * @return  Buffer holding the DER certificate on success.
 * @return  0 when chain is NULL or idx is out of range.
 */
byte* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN* chain, int idx)
{
    byte* cert = NULL;

    WOLFSSL_ENTER("wolfSSL_get_chain_cert");

    if ((chain != NULL) && (idx >= 0) && (idx < chain->count)) {
        /* DER buffer of the certificate stored at the given index. */
        cert = chain->certs[idx].buffer;
    }

    return cert;
}


/* Decode DER certificate data into a WOLFSSL_X509 object. Defined in
 * src/ssl.c. */
static int DecodeToX509(WOLFSSL_X509* x509, const byte* in, int len);

/* Get the certificate at an index in a chain as a new X509 object.
 *
 * The returned object must be freed by the caller with wolfSSL_X509_free().
 *
 * @param [in] chain  Certificate chain object.
 * @param [in] idx    Index of the certificate in the chain.
 * @return  Newly allocated X509 certificate object on success.
 * @return  NULL when chain is NULL, idx is out of range or on error.
 */
WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN* chain, int idx)
{
    WOLFSSL_X509* x509 = NULL;

    WOLFSSL_ENTER("wolfSSL_get_chain_X509");

    if ((chain != NULL) && (idx >= 0) && (idx < chain->count)) {
        x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
            DYNAMIC_TYPE_X509);
        if (x509 == NULL) {
            WOLFSSL_MSG("Failed alloc X509");
        }
        else {
            /* Pre-init with dynamicMemory=1 so DecodeToX509 skips its own
             * InitX509 (and we still own the buffer for X509_free). */
            InitX509(x509, 1, NULL);
            if (DecodeToX509(x509, chain->certs[idx].buffer,
                             chain->certs[idx].length) != 0) {
                WOLFSSL_MSG("Failed to decode cert");
                wolfSSL_X509_free(x509);
                x509 = NULL;
            }
        }
    }

    return x509;
}


/* Get the certificate at an index in a chain as PEM.
 *
 * When buf is NULL, the length required is returned in outLen.
 *
 * @param [in]  chain   Certificate chain object.
 * @param [in]  idx     Index of the certificate in the chain.
 * @param [out] buf     Buffer to hold PEM. May be NULL to get the length.
 * @param [in]  inLen   Length of buffer in bytes.
 * @param [out] outLen  Length of PEM data in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  LENGTH_ONLY_E when buf is NULL and outLen has been set.
 * @return  BAD_FUNC_ARG when a required argument is NULL or idx is invalid.
 * @return  WOLFSSL_FAILURE on error.
 */
int  wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN* chain, int idx,
                               unsigned char* buf, int inLen, int* outLen)
{
    #ifdef WOLFSSL_DER_TO_PEM
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_get_chain_cert_pem");
    if ((chain == NULL) || (outLen == NULL) || (idx < 0) ||
            (idx >= wolfSSL_get_chain_count(chain))) {
        ret = BAD_FUNC_ARG;
    }
    /* Delegate to wc_DerToPem when DER-to-PEM is available. */
    if (ret == WOLFSSL_SUCCESS) {
        if (buf == NULL) {
            inLen = 0;
        }
        else if (inLen < 0) {
            ret = BAD_FUNC_ARG;
        }
    }
    if (ret == WOLFSSL_SUCCESS) {
        int n = wc_DerToPem(chain->certs[idx].buffer,
            (word32)chain->certs[idx].length, buf, (word32)inLen, CERT_TYPE);
        if (n < 0) {
            if (buf == NULL) {
                ret = WOLFSSL_FAILURE;
            }
            else {
                ret = n;
            }
        }
        else {
            *outLen = n;
            if (buf == NULL) {
                ret = WC_NO_ERR_TRACE(LENGTH_ONLY_E);
            }
        }
    }

    return ret;
    #elif defined(WOLFSSL_PEM_TO_DER)
    int ret = WOLFSSL_SUCCESS;
    const char* header = NULL;
    const char* footer = NULL;
    int headerLen;
    int footerLen;
    int i;
    int err;

    WOLFSSL_ENTER("wolfSSL_get_chain_cert_pem");
    if ((chain == NULL) || (outLen == NULL) || (idx < 0) ||
            (idx >= wolfSSL_get_chain_count(chain))) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == WOLFSSL_SUCCESS) {
        if ((err = wc_PemGetHeaderFooter(CERT_TYPE, &header, &footer)) != 0) {
            ret = err;
        }
    }
    if (ret == WOLFSSL_SUCCESS) {
        headerLen = (int)XSTRLEN(header);
        footerLen = (int)XSTRLEN(footer);

        /* Null output buffer returns size needed in outLen. */
        if (buf == NULL) {
            word32 szNeeded = 0;

            if (Base64_Encode(chain->certs[idx].buffer,
                    (word32)chain->certs[idx].length, NULL,
                    &szNeeded) != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
                ret = WOLFSSL_FAILURE;
            }
            else {
                *outLen = (int)szNeeded + headerLen + footerLen;
                ret = WC_NO_ERR_TRACE(LENGTH_ONLY_E);
            }
        }
        /* buf == NULL, ret will not be WOLFSSL_SUCCESS. */
    }
    /* Don't even try when inLen is too short. */
    if ((ret == WOLFSSL_SUCCESS) &&
            (inLen < headerLen + footerLen + chain->certs[idx].length)) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == WOLFSSL_SUCCESS) {
        /* Write the PEM header. */
        XMEMCPY(buf, header, (size_t)headerLen);
        i = headerLen;

        /* Space left for Base64 data after header and before footer. */
        *outLen = inLen - headerLen - footerLen;
        if ((err = Base64_Encode(chain->certs[idx].buffer,
                (word32)chain->certs[idx].length, buf + i,
                (word32*)outLen)) < 0) {
            ret = err;
        }
    }
    if (ret == WOLFSSL_SUCCESS) {
        i += *outLen;

        /* Write the PEM footer. */
        XMEMCPY(buf + i, footer, (size_t)footerLen);
        *outLen += headerLen + footerLen;
    }

    return ret;
    #else
    (void)chain;
    (void)idx;
    (void)buf;
    (void)inLen;
    (void)outLen;
    return WOLFSSL_FAILURE;
    #endif /* WOLFSSL_PEM_TO_DER || WOLFSSL_DER_TO_PEM */
}

#endif /* SESSION_CERTS */


#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX) || defined(WOLFSSL_QT)
#ifndef NO_WOLFSSL_STUB
/* Clear the extra certificate chain set on the context.
 *
 * Not implemented - stub for OpenSSL compatibility.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  Result of the SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS control command.
 */
long wolfSSL_CTX_clear_extra_chain_certs(WOLFSSL_CTX* ctx)
{
    return wolfSSL_CTX_ctrl(ctx, SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS, 0L, NULL);
}
#endif

/* Get the verify callback set on the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Verify callback on success.
 * @return  NULL when ssl is NULL or no callback is set.
 */
VerifyCallback wolfSSL_get_verify_callback(WOLFSSL* ssl)
{
    VerifyCallback cb = NULL;

    WOLFSSL_ENTER("wolfSSL_get_verify_callback");

    if (ssl != NULL) {
        /* Verify callback configured on the object. */
        cb = ssl->verifyCallback;
    }

    return cb;
}

#endif

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
/* Get the verify callback set on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  Verify callback on success.
 * @return  NULL when ctx is NULL or no callback is set.
 */
VerifyCallback wolfSSL_CTX_get_verify_callback(WOLFSSL_CTX* ctx)
{
    VerifyCallback cb = NULL;

    WOLFSSL_ENTER("wolfSSL_CTX_get_verify_callback");

    if (ctx != NULL) {
        /* Verify callback configured on the context. */
        cb = ctx->verifyCallback;
    }

    return cb;
}

#endif

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(WOLFSSL_NGINX)

/* Get the verification mode set on the object.
 *
 * WOLFSSL_VERIFY_CLIENT_ONCE is never reported: wolfSSL_set_verify() accepts
 * and ignores it rather than storing it. Neither is WOLFSSL_VERIFY_DEFAULT -
 * it clears every option, so a mode of 0 is returned for it.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Bitmask of WOLFSSL_VERIFY_* flags on success.
 * @return  WOLFSSL_FAILURE when ssl is NULL.
 */
int wolfSSL_get_verify_mode(const WOLFSSL* ssl)
{
    int mode = 0;

    WOLFSSL_ENTER("wolfSSL_get_verify_mode");

    if (ssl == NULL) {
        mode = WOLFSSL_FAILURE;
    }
    else if (ssl->options.verifyNone) {
        /* VERIFY_NONE is exclusive of the other verify flags. */
        mode = WOLFSSL_VERIFY_NONE;
    }
    else {
        /* Build the mode as a bitmask of the enabled verify flags. */
        if (ssl->options.verifyPeer) {
            mode |= WOLFSSL_VERIFY_PEER;
        }
        if (ssl->options.failNoCert) {
            mode |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        if (ssl->options.failNoCertxPSK) {
            mode |= WOLFSSL_VERIFY_FAIL_EXCEPT_PSK;
        }
        #if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
        if (ssl->options.verifyPostHandshake) {
            mode |= WOLFSSL_VERIFY_POST_HANDSHAKE;
        }
        #endif
    }

    WOLFSSL_LEAVE("wolfSSL_get_verify_mode", mode);
    return mode;
}

/* Get the verification mode set on the context.
 *
 * WOLFSSL_VERIFY_CLIENT_ONCE is never reported: wolfSSL_CTX_set_verify()
 * accepts and ignores it rather than storing it. Neither is
 * WOLFSSL_VERIFY_DEFAULT - it clears every option, so a mode of 0 is
 * returned for it.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  Bitmask of WOLFSSL_VERIFY_* flags on success.
 * @return  WOLFSSL_FAILURE when ctx is NULL.
 */
int wolfSSL_CTX_get_verify_mode(const WOLFSSL_CTX* ctx)
{
    int mode = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_get_verify_mode");

    if (ctx == NULL) {
        mode = WOLFSSL_FAILURE;
    }
    else if (ctx->verifyNone) {
        /* VERIFY_NONE is exclusive of the other verify flags. */
        mode = WOLFSSL_VERIFY_NONE;
    }
    else {
        /* Build the mode as a bitmask of the enabled verify flags. */
        if (ctx->verifyPeer) {
            mode |= WOLFSSL_VERIFY_PEER;
        }
        if (ctx->failNoCert) {
            mode |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        if (ctx->failNoCertxPSK) {
            mode |= WOLFSSL_VERIFY_FAIL_EXCEPT_PSK;
        }
        #if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
        if (ctx->verifyPostHandshake) {
            mode |= WOLFSSL_VERIFY_POST_HANDSHAKE;
        }
        #endif
    }

    WOLFSSL_LEAVE("wolfSSL_CTX_get_verify_mode", mode);
    return mode;
}

#endif


#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
/* Create a stack of X509 certificates from a DER encoded certificate chain.
 *
 * The chain buffer holds each certificate as: 3 byte length | X509 DER data.
 *
 * @param [in]  der     DER encoded certificate chain.
 * @param [in]  derLen  Length of certificate chain buffer in bytes.
 * @param [in]  heap    Dynamic memory hint.
 * @param [out] chain   Stack of X509 certificates. Holds as much of the
 *                      chain as was created on failure.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE on allocation or decode error.
 */
static int wolfssl_certchain_to_x509_stack(byte* der, word32 derLen,
    void* heap, WOLF_STACK_OF(X509)** chain)
{
    int            ret = WOLFSSL_SUCCESS;
    word32         idx;
    word32         length;
    WOLFSSL_STACK* node;
    WOLFSSL_STACK* last = NULL;

    /* Create a new stack of WOLFSSL_X509 object from chain buffer. */
    for (idx = 0; idx < derLen; ) {
        /* Need 3 bytes for the length of the DER encoded certificate. */
        if ((derLen - idx) < 3) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        /* Format: 3 byte length | X509 DER data. */
        ato24(der + idx, &length);
        idx += 3;

        /* Ensure the DER encoded certificate is contained in the buffer. */
        if (length > (derLen - idx)) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        node = wolfSSL_sk_X509_new_null();
        if (node == NULL) {
            ret = WOLFSSL_FAILURE;
            break;
        }
        node->next = NULL;

        /* Create a new X509 from DER encoded data. */
        node->data.x509 = wolfSSL_X509_d2i_ex(NULL, der + idx, (int)length,
            heap);
        if (node->data.x509 == NULL) {
            XFREE(node, NULL, DYNAMIC_TYPE_OPENSSL);
            /* Return as much of the chain as we created. */
            ret = WOLFSSL_FAILURE;
            break;
        }
        idx += length;

        /* Add object to the end of the stack. */
        if (last == NULL) {
            node->num = 1;
            *chain = node;
        }
        else {
            (*chain)->num++;
            last->next = node;
        }

        last = node;
    }

    return ret;
}

/* Get the extra certificate chain set on the context as a stack of X509.
 *
 * Builds the stack from the context's certificate chain buffer when needed.
 *
 * @param [in]  ctx    SSL/TLS context object.
 * @param [out] chain  Stack of X509 certificates.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx or chain is NULL, or on allocation error.
 */
int wolfSSL_CTX_get_extra_chain_certs(WOLFSSL_CTX* ctx,
    WOLF_STACK_OF(X509)** chain)
{
    int ret = WOLFSSL_SUCCESS;

    if ((ctx == NULL) || (chain == NULL)) {
        ret = WOLFSSL_FAILURE;
    }
    else if (ctx->x509Chain != NULL) {
        *chain = ctx->x509Chain;
    }
    else {
        /* If there are no chains then success! */
        *chain = NULL;
        if ((ctx->certChain != NULL) && (ctx->certChain->length != 0)) {
            /* Build a stack of X509 from the DER certificate chain buffer. */
            ret = wolfssl_certchain_to_x509_stack(ctx->certChain->buffer,
                ctx->certChain->length, ctx->heap, chain);
            /* Cache the chain - holds as much as was created on failure. */
            ctx->x509Chain = *chain;
        }
    }

    return ret;
}

/* Get the certificate chain set on the context.
 *
 * @param [in]  ctx  SSL/TLS context object.
 * @param [out] sk   Stack of X509 certificates.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx or sk is NULL.
 */
int wolfSSL_CTX_get0_chain_certs(WOLFSSL_CTX *ctx,
        WOLF_STACK_OF(WOLFSSL_X509) **sk)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_get0_chain_certs");

    if ((ctx == NULL) || (sk == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        ret = WOLFSSL_FAILURE;
    }
    else {
        /* This function should return ctx->x509Chain if it is populated,
         * otherwise it should be populated from ctx->certChain.  This matches
         * the behavior of wolfSSL_CTX_get_extra_chain_certs, so it is used
         * directly. */
        ret = wolfSSL_CTX_get_extra_chain_certs(ctx, sk);
    }

    return ret;
}

#ifdef KEEP_OUR_CERT
/* Get our certificate chain set on the object.
 *
 * @param [in]  ssl  SSL/TLS object.
 * @param [out] sk   Stack of X509 certificates.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl or sk is NULL.
 */
int wolfSSL_get0_chain_certs(WOLFSSL *ssl, WOLF_STACK_OF(WOLFSSL_X509) **sk)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_get0_chain_certs");

    if ((ssl == NULL) || (sk == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        ret = WOLFSSL_FAILURE;
    }
    else {
        /* Return our own certificate chain held on the object. */
        *sk = ssl->ourCertChain;
    }

    return ret;
}
#endif

#endif

#ifdef WOLFSSL_CERT_SETUP_CB
/* ctx->CBClientCert is only in the structure under OPENSSL_EXTRA, so the
 * setter cannot be compiled more widely than that. */
#ifdef OPENSSL_EXTRA
/* Set the callback that supplies a client certificate and key.
 *
 * Called during the handshake when the server asks for client authentication
 * and no certificate and key have been loaded.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Callback to call. NULL to clear.
 */
void wolfSSL_CTX_set_client_cert_cb(WOLFSSL_CTX *ctx, client_cert_cb cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_client_cert_cb");

    if (ctx != NULL) {
        ctx->CBClientCert = cb;
    }
}
#endif

/* Set the certificate setup callback on the SSL/TLS CTX object.
 *
 * The callback is called during the handshake to allow the certificate and
 * key to be chosen or loaded on demand.
 *
 * @param [in, out] ctx  SSL/TLS CTX object.
 * @param [in]      cb   Certificate setup callback. NULL to clear.
 * @param [in]      arg  Context to pass to the callback.
 */
void wolfSSL_CTX_set_cert_cb(WOLFSSL_CTX* ctx,
    CertSetupCallback cb, void *arg)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_cert_cb");

    if (ctx != NULL) {
        ctx->certSetupCb = cb;
        ctx->certSetupCbArg = arg;
    }
}

/* Call the certificate setup callback and translate its result.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  0 when no callback is set or the callback reported success.
 * @return  CLIENT_CERT_CB_ERROR when the callback failed or returned an
 *          unrecognized value. A fatal alert is sent when it failed.
 * @return  WOLFSSL_ERROR_WANT_X509_LOOKUP when the callback returned a
 *          negative value to ask to be called again.
 */
int CertSetupCbWrapper(WOLFSSL* ssl)
{
    int ret = 0;

    if (ssl->ctx->certSetupCb != NULL) {
        WOLFSSL_MSG("Calling user cert setup callback");
        ret = ssl->ctx->certSetupCb(ssl, ssl->ctx->certSetupCbArg);
        if (ret == 1) {
            WOLFSSL_MSG("User cert callback returned success");
            ret = 0;
        }
        else if (ret == 0) {
            SendAlert(ssl, alert_fatal, internal_error);
            ret = CLIENT_CERT_CB_ERROR;
        }
        else if (ret < 0) {
            ret = WOLFSSL_ERROR_WANT_X509_LOOKUP;
        }
        else {
            WOLFSSL_MSG("Unexpected user callback return");
            ret = CLIENT_CERT_CB_ERROR;
        }
    }
    return ret;
}
#endif /* WOLFSSL_CERT_SETUP_CB */


#ifdef SESSION_CERTS
/* Decode the X509 DER encoded certificate into a WOLFSSL_X509 object.
 *
 * @param [in, out] x509  WOLFSSL_X509 object to decode into.
 * @param [in]      in    X509 DER data.
 * @param [in]      len   Length of the X509 DER data.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when x509 or in is NULL, or len is not positive.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other negative value when the certificate cannot be parsed.
 */
static int DecodeToX509(WOLFSSL_X509* x509, const byte* in, int len)
{
    int ret = 0;
    WC_DECLARE_VAR(cert, DecodedCert, 1, 0);

    /* Validate parameters. */
    if ((x509 == NULL) || (in == NULL) || (len <= 0)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        WC_ALLOC_VAR_EX(cert, DecodedCert, 1, NULL, DYNAMIC_TYPE_DCERT,
            ret = MEMORY_E);
    }

    if (ret == 0) {
        /* Create a DecodedCert object and copy fields into WOLFSSL_X509
         * object. */
        InitDecodedCert(cert, (byte*)in, (word32)len, NULL);
        ret = ParseCertRelative(cert, CERT_TYPE, 0, NULL, NULL);
        if (ret == 0) {
        /* Check if x509 was not previously initialized by wolfSSL_X509_new() */
            if (x509->dynamicMemory != TRUE) {
                /* A non-dynamic x509 (e.g. ssl->peerCert) may already hold
                 * decoded contents; free them before re-populating. ReinitX509
                 * keeps the object's heap and reference state, as the object
                 * may be referenced elsewhere. */
                ReinitX509(x509);
            }
            ret = CopyDecodedToX509(x509, cert);
        }
        FreeDecodedCert(cert);
        WC_FREE_VAR_EX(cert, NULL, DYNAMIC_TYPE_DCERT);
    }

    return ret;
}
#endif /* SESSION_CERTS */


#ifdef KEEP_PEER_CERT
/* Get a copy of the peer's certificate.
 *
 * The certificate is decoded from the session chain when not already
 * available on the object. Caller must free the returned certificate with
 * wolfSSL_X509_free().
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  Peer's X509 certificate on success.
 * @return  NULL when ssl is NULL, no peer certificate was kept or dynamic
 *          memory allocation fails.
 */
WOLFSSL_ABI
WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl)
{
    WOLFSSL_X509* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_get_peer_certificate");

    if (ssl != NULL) {
        if (ssl->peerCert.issuer.sz > 0) {
            ret = wolfSSL_X509_dup(&ssl->peerCert);
        }
        #ifdef SESSION_CERTS
        else if (ssl->session->chain.count > 0) {
            if (DecodeToX509(&ssl->peerCert,
                    ssl->session->chain.certs[0].buffer,
                    ssl->session->chain.certs[0].length) == 0) {
                ret = wolfSSL_X509_dup(&ssl->peerCert);
            }
        }
        #endif
    }
    WOLFSSL_LEAVE("wolfSSL_get_peer_certificate", ret != NULL);
    return ret;
}

#endif /* KEEP_PEER_CERT */

/* NO_CERTS is part of the guard so that the declaration of
 * x509GetIssuerFromCM() in src/ssl.c, its definition in src/x509_str.c and
 * the call below all agree on when they exist. */
#if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA) && !defined(NO_CERTS)
/* Get the stack of the peer's certificates.
 *
 * The stack is owned by the SSL/TLS object and is disposed of with it, so the
 * caller must not free it.
 *
 * @param [in, out] ssl  SSL/TLS object. Declared const, but the chain is
 *                       built into it on the first call.
 * @return  Stack of the peer's certificates on success.
 * @return  NULL when ssl is NULL or no chain was received.
 */
WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_get_peer_cert_chain(const WOLFSSL* ssl)
{
    WOLF_STACK_OF(WOLFSSL_X509)* ret = NULL;

    WOLFSSL_ENTER("wolfSSL_get_peer_cert_chain");

    if (ssl != NULL) {
        /* Try to populate when not present or empty. */
        if ((ssl->peerCertChain == NULL) ||
                (wolfSSL_sk_X509_num(ssl->peerCertChain) == 0)) {
            wolfSSL_set_peer_cert_chain((WOLFSSL*)ssl);
        }
        ret = ssl->peerCertChain;
    }

    return ret;
}

/* Push the chain of issuing CAs onto the stack.
 *
 * Each certificate's issuer is looked up in turn, stopping when no further
 * issuer is known or the maximum chain depth is reached.
 *
 * @param [in]      cm  Certificate manager queried for each issuer.
 * @param [in]      x   Certificate whose issuer is looked up first.
 * @param [in, out] sk  Stack the issuers are pushed onto.
 * @return  0 on success or when no issuer was found.
 * @return  WOLFSSL_FATAL_ERROR when an issuer could not be pushed.
 */
static int PushCAx509Chain(WOLFSSL_CERT_MANAGER* cm,
        WOLFSSL_X509 *x, WOLFSSL_STACK* sk)
{
    int ret = 0;
    int i;

    for (i = 0; (ret == 0) && (i < MAX_CHAIN_DEPTH); i++) {
        WOLFSSL_X509* issuer = NULL;

        /* No more issuers known - chain is as complete as it can be. */
        if (x509GetIssuerFromCM(&issuer, cm, x) != WOLFSSL_SUCCESS) {
            break;
        }
        if (wolfSSL_sk_X509_push(sk, issuer) <= 0) {
            /* Not stored on the stack - dispose of it here. */
            wolfSSL_X509_free(issuer);
            ret = WOLFSSL_FATAL_ERROR;
        }
        else {
            x = issuer;
        }
    }

    return ret;
}


/* Decode one certificate of the session chain onto the stack.
 *
 * On the last certificate of a verified chain the CA chain known for it is
 * appended as well.
 *
 * @param [in]      ssl           SSL/TLS object.
 * @param [in]      idx           Index of the certificate in the chain.
 * @param [in]      verifiedFlag  Whether to append the known CA chain.
 * @param [in, out] sk            Stack to add the certificate to.
 * @return  0 on success.
 * @return  MEMORY_E when the certificate object cannot be created.
 * @return  Other negative value when the certificate cannot be decoded or
 *          stored.
 */
static int PushPeerCertToChain(const WOLFSSL* ssl, int idx, int verifiedFlag,
    WOLFSSL_STACK* sk)
{
    int ret;
    WOLFSSL_X509* x509 = wolfSSL_X509_new_ex(ssl->heap);

    if (x509 == NULL) {
        WOLFSSL_MSG("Error Creating X509");
        ret = MEMORY_E;
    }
    else {
        ret = DecodeToX509(x509, ssl->session->chain.certs[idx].buffer,
            ssl->session->chain.certs[idx].length);
        if (ret == 0) {
            if (wolfSSL_sk_X509_push(sk, x509) <= 0) {
                ret = WOLFSSL_FATAL_ERROR;
            }
            else {
                if ((idx == ssl->session->chain.count - 1) &&
                        (verifiedFlag)) {
                    /* On the last certificate of a verified chain, append the
                     * CA chain known for it. The certificate is needed to look
                     * the issuers up, so this is done before the reference to
                     * it is dropped below. */
                    SSL_CM_WARNING(ssl);
                    ret = PushCAx509Chain(SSL_CM(ssl), x509, sk);
                }
                /* The stack owns the certificate from here on. */
                x509 = NULL;
            }
        }
        if (ret != 0) {
            WOLFSSL_MSG("Error decoding cert");
            /* NULL once the stack has taken ownership, and freeing NULL does
             * nothing, so this only releases a certificate that never got
             * there. */
            wolfSSL_X509_free(x509);
        }
    }

    return ret;
}

/* Build a stack of the peer's certificates from the session chain.
 *
 * For a verified chain the CA certificates known for the last certificate are
 * placed at the bottom of the stack.
 *
 * @param [in] ssl           SSL/TLS object.
 * @param [in] verifiedFlag  Whether to append the known CA chain.
 * @return  Stack of the peer's certificates on success.
 * @return  NULL when ssl is NULL, the session holds no chain, or a certificate
 *          cannot be created, decoded or stored.
 */
static WOLF_STACK_OF(WOLFSSL_X509)* CreatePeerCertChain(const WOLFSSL* ssl,
    int verifiedFlag)
{
    WOLFSSL_STACK* sk = NULL;
    int err = 0;

    WOLFSSL_ENTER("CreatePeerCertChain");

    /* There is nothing to build from without a session chain. */
    if ((ssl == NULL) || (ssl->session->chain.count == 0)) {
        err = 1;
    }
    else {
        sk = wolfSSL_sk_X509_new_null();
        if (sk == NULL) {
            WOLFSSL_MSG("Error creating stack");
            err = 1;
        }
    }

    if (!err) {
        int i;

        for (i = 0; i < ssl->session->chain.count; i++) {
            if (PushPeerCertToChain(ssl, i, verifiedFlag, sk) != 0) {
                err = 1;
                break;
            }
        }
    }

    if (err) {
        /* Certificates already pushed are freed with the stack. */
        wolfSSL_sk_X509_pop_free(sk, NULL);
        sk = NULL;
    }

    return sk;
}


/* Build and store the stack of the peer's certificates.
 *
 * On the server the leaf certificate is moved out of the stack and kept as the
 * session's peer. The stack is disposed of when the SSL/TLS object is.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  Stack of the peer's certificates on success.
 * @return  NULL when ssl is NULL, the session holds no chain, or the stack
 *          cannot be built.
 */
WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_set_peer_cert_chain(WOLFSSL* ssl)
{
    WOLFSSL_STACK* sk = NULL;

    WOLFSSL_ENTER("wolfSSL_set_peer_cert_chain");

    /* Validate parameters. */
    if ((ssl != NULL) && (ssl->session->chain.count > 0)) {
        sk = CreatePeerCertChain(ssl, 0);
    }

    if (sk != NULL) {
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            /* Replace any peer kept from a previous call. */
            if (ssl->session->peer != NULL) {
                wolfSSL_X509_free(ssl->session->peer);
            }

            ssl->session->peer = wolfSSL_sk_X509_shift(sk);
            ssl->session->peerVerifyRet = ssl->peerVerifyRet;
        }
        if (ssl->peerCertChain != NULL) {
            wolfSSL_sk_X509_pop_free(ssl->peerCertChain, NULL);
        }
        /* This is Free'd when ssl is Free'd */
        ssl->peerCertChain = sk;
    }

    return sk;
}

#ifdef KEEP_PEER_CERT
/* Get the peer's certificate chain, verified against the store.
 *
 * Implemented in a similar way to ngx_ssl_ocsp_validate() when
 * SSL_get0_verified_chain is not available. The chain is stored on the SSL/TLS
 * object and disposed of with it, so the caller must not free it.
 *
 * @param [in, out] ssl  SSL/TLS object. Declared const, but the verified
 *                       chain is stored into it.
 * @return  Stack of verified certificates on success.
 * @return  NULL when ssl or its context is NULL, no peer certificate was kept,
 *          the chain cannot be built, or verification fails.
 */
WOLF_STACK_OF(WOLFSSL_X509) *wolfSSL_get0_verified_chain(const WOLFSSL *ssl)
{
    WOLF_STACK_OF(WOLFSSL_X509)* chain = NULL;
    WOLFSSL_X509_STORE_CTX* storeCtx = NULL;
    WOLFSSL_X509* peerCert = NULL;
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_get0_verified_chain");

    /* Validate parameters. */
    if ((ssl == NULL) || (ssl->ctx == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        err = 1;
    }

    if (!err) {
        peerCert = wolfSSL_get_peer_certificate((WOLFSSL*)ssl);
        if (peerCert == NULL) {
            WOLFSSL_MSG("wolfSSL_get_peer_certificate error");
            err = 1;
        }
        else {
            /* wolfSSL_get_peer_certificate returns a copy. We want the
             * internal member so that we don't have to worry about free'ing
             * it. We call wolfSSL_get_peer_certificate so that we don't have
             * to worry about setting up the internal pointer. */
            wolfSSL_X509_free(peerCert);
            peerCert = (WOLFSSL_X509*)&ssl->peerCert;
        }
    }

    if (!err) {
        chain = CreatePeerCertChain((WOLFSSL*)ssl, 1);
        if (chain == NULL) {
            WOLFSSL_MSG("wolfSSL_get_peer_cert_chain error");
            err = 1;
        }
        else {
            /* Replace any chain kept from a previous call. */
            if (ssl->verifiedChain != NULL) {
                wolfSSL_sk_X509_pop_free(ssl->verifiedChain, NULL);
            }
            /* This is Free'd when ssl is Free'd */
            ((WOLFSSL*)ssl)->verifiedChain = chain;
        }
    }

    if (!err) {
        storeCtx = wolfSSL_X509_STORE_CTX_new();
        if (storeCtx == NULL) {
            WOLFSSL_MSG("wolfSSL_X509_STORE_CTX_new error");
            err = 1;
        }
    }

    if (!err) {
        if (wolfSSL_X509_STORE_CTX_init(storeCtx, SSL_STORE(ssl), peerCert,
                chain) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_X509_STORE_CTX_init error");
            err = 1;
        }
        else if (wolfSSL_X509_verify_cert(storeCtx) <= 0) {
            WOLFSSL_MSG("wolfSSL_X509_verify_cert error");
            err = 1;
        }
    }

    wolfSSL_X509_STORE_CTX_free(storeCtx);
    if (err) {
        /* The chain stays owned by the object; report failure only. */
        chain = NULL;
    }

    return chain;
}
#endif /* KEEP_PEER_CERT */
#endif /* SESSION_CERTS && OPENSSL_EXTRA && !NO_CERTS */

#endif /* !WOLFCRYPT_ONLY */

#endif /* !WOLFSSL_SSL_API_CERT_INCLUDED */
