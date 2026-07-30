/* ssl_api_crl_ocsp.c
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

#if !defined(WOLFSSL_SSL_API_CRL_OCSP_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_api_crl_ocsp.c is not compiled separately from ssl.c
    #endif
#else

#ifndef NO_CERTS

#ifdef HAVE_CRL

/* Load a CRL from a buffer into the context.
 *
 * @param [in, out] ctx   SSL/TLS context.
 * @param [in]      buff  Buffer holding the CRL.
 * @param [in]      sz    Length of the buffer in bytes.
 * @param [in]      type  Format of the data: PEM or DER.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_LoadCRLBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff,
                              long sz, int type)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_LoadCRLBuffer");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerLoadCRLBuffer(ctx->cm, buff, sz, type);
    }

    return ret;
}


/* Load a CRL from a buffer into the object.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      buff  Buffer holding the CRL.
 * @param [in]      sz    Length of the buffer in bytes.
 * @param [in]      type  Format of the data: PEM or DER.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl or its context is NULL.
 */
int wolfSSL_LoadCRLBuffer(WOLFSSL* ssl, const unsigned char* buff,
                          long sz, int type)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_LoadCRLBuffer");

    if ((ssl == NULL) || (ssl->ctx == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerLoadCRLBuffer(SSL_CM(ssl), buff, sz, type);
    }

    return ret;
}

/* Turn on CRL checking for the object.
 *
 * @param [in, out] ssl      SSL/TLS object.
 * @param [in]      options  Options to apply.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_EnableCRL(WOLFSSL* ssl, int options)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_EnableCRL");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerEnableCRL(SSL_CM(ssl), options);
    }

    return ret;
}


/* Turn off CRL checking for the object.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_DisableCRL(WOLFSSL* ssl)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_DisableCRL");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerDisableCRL(SSL_CM(ssl));
    }

    return ret;
}

#ifndef NO_FILESYSTEM
/* Load CRLs from a directory into the object.
 *
 * @param [in, out] ssl      SSL/TLS object.
 * @param [in]      path     Path of the directory to load CRLs from.
 * @param [in]      type     Format of the data: PEM or DER.
 * @param [in]      monitor  Whether to monitor the directory for changes.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type, int monitor)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_LoadCRL");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerLoadCRL(SSL_CM(ssl), path, type, monitor);
    }

    return ret;
}

/* Load a CRL from a file into the object.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      file  Path of the file to load the CRL from.
 * @param [in]      type  Format of the data: PEM or DER.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_LoadCRLFile(WOLFSSL* ssl, const char* file, int type)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_LoadCRLFile");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerLoadCRLFile(SSL_CM(ssl), file, type);
    }

    return ret;
}
#endif

/* Set the callback called when a CRL is missing.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      cb   Callback to call. NULL to clear.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_SetCRL_Cb(WOLFSSL* ssl, CbMissingCRL cb)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_SetCRL_Cb");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerSetCRL_Cb(SSL_CM(ssl), cb);
    }

    return ret;
}

/* Set the callback called when a CRL check fails.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      cb   Callback to call. NULL to clear.
 * @param [in]      ctx  Context to pass to the callback.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_SetCRL_ErrorCb(WOLFSSL* ssl, crlErrorCb cb, void* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_SetCRL_ErrorCb");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerSetCRL_ErrorCb(SSL_CM(ssl), cb, ctx);
    }

    return ret;
}

#ifdef HAVE_CRL_IO
/* Set the callback used to fetch a CRL.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      cb   Callback to call. NULL to clear.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_SetCRL_IOCb(WOLFSSL* ssl, CbCrlIO cb)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_SetCRL_IOCb");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerSetCRL_IOCb(SSL_CM(ssl), cb);
    }

    return ret;
}
#endif

/* Turn on CRL checking for the context.
 *
 * @param [in, out] ctx      SSL/TLS context.
 * @param [in]      options  Options to apply.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_EnableCRL");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerEnableCRL(ctx->cm, options);
    }

    return ret;
}


/* Turn off CRL checking for the context.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_DisableCRL");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerDisableCRL(ctx->cm);
    }

    return ret;
}


#ifndef NO_FILESYSTEM
/* Load CRLs from a directory into the context.
 *
 * @param [in, out] ctx      SSL/TLS context.
 * @param [in]      path     Path of the directory to load CRLs from.
 * @param [in]      type     Format of the data: PEM or DER.
 * @param [in]      monitor  Whether to monitor the directory for changes.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX* ctx, const char* path,
                        int type, int monitor)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_LoadCRL");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerLoadCRL(ctx->cm, path, type, monitor);
    }

    return ret;
}

/* Load a CRL from a file into the context.
 *
 * @param [in, out] ctx   SSL/TLS context.
 * @param [in]      file  Path of the file to load the CRL from.
 * @param [in]      type  Format of the data: PEM or DER.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_LoadCRLFile(WOLFSSL_CTX* ctx, const char* file,
                        int type)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_LoadCRLFile");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerLoadCRLFile(ctx->cm, file, type);
    }

    return ret;
}
#endif


/* Set the callback called when a CRL is missing.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @param [in]      cb   Callback to call. NULL to clear.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX* ctx, CbMissingCRL cb)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_SetCRL_Cb");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerSetCRL_Cb(ctx->cm, cb);
    }

    return ret;
}

/* Set the callback called when a CRL check fails.
 *
 * @param [in, out] ctx    SSL/TLS context.
 * @param [in]      cb     Callback to call. NULL to clear.
 * @param [in]      cbCtx  Context to pass to the callback.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_SetCRL_ErrorCb(WOLFSSL_CTX* ctx, crlErrorCb cb, void* cbCtx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_SetCRL_ErrorCb");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerSetCRL_ErrorCb(ctx->cm, cb, cbCtx);
    }

    return ret;
}

#ifdef HAVE_CRL_IO
/* Set the callback used to fetch a CRL.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @param [in]      cb   Callback to call. NULL to clear.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_SetCRL_IOCb(WOLFSSL_CTX* ctx, CbCrlIO cb)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_SetCRL_IOCb");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerSetCRL_IOCb(ctx->cm, cb);
    }

    return ret;
}
#endif

#endif /* HAVE_CRL */


#ifdef HAVE_OCSP
/* Turn on OCSP checking for the object.
 *
 * @param [in, out] ssl      SSL/TLS object.
 * @param [in]      options  Options to apply.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_EnableOCSP(WOLFSSL* ssl, int options)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_EnableOCSP");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerEnableOCSP(SSL_CM(ssl), options);
    }

    return ret;
}

/* Turn off OCSP checking for the object.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_DisableOCSP(WOLFSSL* ssl)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_DisableOCSP");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerDisableOCSP(SSL_CM(ssl));
    }

    return ret;
}


/* Turn on OCSP stapling for the object.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_EnableOCSPStapling(WOLFSSL* ssl)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_EnableOCSPStapling");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerEnableOCSPStapling(SSL_CM(ssl));
    }

    return ret;
}

/* Turn off OCSP stapling for the object.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_DisableOCSPStapling(WOLFSSL* ssl)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_DisableOCSPStapling");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerDisableOCSPStapling(SSL_CM(ssl));
    }

    return ret;
}
/* Set the responder URL to use instead of the one in the certificate.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      url  URL of the responder to use.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_SetOCSP_OverrideURL");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ret = wolfSSL_CertManagerSetOCSPOverrideURL(SSL_CM(ssl), url);
    }

    return ret;
}


/* Set the callbacks used to fetch and release an OCSP response.
 *
 * @param [in, out] ssl         SSL/TLS object.
 * @param [in]      ioCb        I/O callback to call. NULL to clear.
 * @param [in]      respFreeCb  Callback that releases a response. NULL to
 *                              clear.
 * @param [in]      ioCbCtx     Context to pass to the I/O callback.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_SetOCSP_Cb(WOLFSSL* ssl,
                        CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_SetOCSP_Cb");

    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        SSL_CM_WARNING(ssl);
        ssl->ocspIOCtx = ioCbCtx; /* use SSL specific ioCbCtx */
        ret = wolfSSL_CertManagerSetOCSP_Cb(SSL_CM(ssl), ioCb, respFreeCb,
            NULL);
    }

    return ret;
}

/* Turn on OCSP checking for the context.
 *
 * @param [in, out] ctx      SSL/TLS context.
 * @param [in]      options  Options to apply.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX* ctx, int options)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_EnableOCSP");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerEnableOCSP(ctx->cm, options);
    }

    return ret;
}


/* Turn off OCSP checking for the context.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_DisableOCSP");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerDisableOCSP(ctx->cm);
    }

    return ret;
}


/* Set the responder URL to use instead of the one in the certificate.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @param [in]      url  URL of the responder to use.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX* ctx, const char* url)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_SetOCSP_OverrideURL");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerSetOCSPOverrideURL(ctx->cm, url);
    }

    return ret;
}


/* Set the callbacks used to fetch and release an OCSP response.
 *
 * @param [in, out] ctx         SSL/TLS context.
 * @param [in]      ioCb        I/O callback to call. NULL to clear.
 * @param [in]      respFreeCb  Callback that releases a response. NULL to
 *                              clear.
 * @param [in]      ioCbCtx     Context to pass to the I/O callback.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX* ctx, CbOCSPIO ioCb,
                           CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_SetOCSP_Cb");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerSetOCSP_Cb(ctx->cm, ioCb,
            respFreeCb, ioCbCtx);
    }

    return ret;
}

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
/* Turn on OCSP stapling for the context.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_EnableOCSPStapling");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerEnableOCSPStapling(ctx->cm);
    }

    return ret;
}

/* Turn off OCSP stapling for the context.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_DisableOCSPStapling(WOLFSSL_CTX* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_DisableOCSPStapling");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerDisableOCSPStapling(ctx->cm);
    }

    return ret;
}
/* Require the peer to staple an OCSP response.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_EnableOCSPMustStaple(WOLFSSL_CTX* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_EnableOCSPMustStaple");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerEnableOCSPMustStaple(ctx->cm);
    }

    return ret;
}

/* Stop requiring the peer to staple an OCSP response.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @return  Result of the certificate manager operation.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_DisableOCSPMustStaple(WOLFSSL_CTX* ctx)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_DisableOCSPMustStaple");

    if (ctx == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wolfSSL_CertManagerDisableOCSPMustStaple(ctx->cm);
    }

    return ret;
}
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST || \
        * HAVE_CERTIFICATE_STATUS_REQUEST_V2 */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
/* Get the OCSP response this side has staged to staple.
 *
 * The response is the one set by wolfSSL_set_tlsext_status_ocsp_resp(), which
 * is what the status callback supplies for the server to send. Nothing stores
 * a response received from the peer here.
 *
 * Not an OpenSSL API.
 *
 * @param [in]  ssl       SSL/TLS object.
 * @param [out] response  Staged response, which is NULL when there is none.
 *                        Written only when both parameters are non-NULL, so
 *                        a caller that passes a NULL ssl is left with
 *                        whatever it had - check the return value before
 *                        reading it.
 * @return  Length of the response, which is zero when there is none or when
 *          a parameter is NULL.
 */
int wolfSSL_get_ocsp_response(WOLFSSL* ssl, byte** response)
{
    int ret = 0;

    if ((ssl != NULL) && (response != NULL)) {
        *response = ssl->ocspCsrResp[0].buffer;
        ret = (int)ssl->ocspCsrResp[0].length;
    }

    return ret;
}

/* Get the OCSP responder URL set on the object.
 *
 * Not an OpenSSL API.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  URL set on the object, which is NULL when none was set or when
 *          ssl is NULL.
 */
char* wolfSSL_get_ocsp_url(WOLFSSL* ssl)
{
    char* ret = NULL;

    if (ssl != NULL) {
        ret = ssl->url;
    }

    return ret;
}

/* Set the OCSP responder URL on the object.
 *
 * The string is not copied, so it must outlive the object.
 *
 * Not an OpenSSL API.
 *
 * @param [in, out] ssl  SSL/TLS object.
 * @param [in]      url  URL to use. NULL to clear.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl is NULL.
 */
int wolfSSL_set_ocsp_url(WOLFSSL* ssl, char* url)
{
    int ret = WOLFSSL_SUCCESS;

    if (ssl == NULL) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        ssl->url = url;
    }

    return ret;
}
#endif /* OPENSSL_ALL || WOLFSSL_NGINX  || WOLFSSL_HAPROXY */

#if !defined(NO_ASN_TIME)
/* Get the date the last OCSP response was produced.
 *
 * @param [in]  ssl                 SSL/TLS object.
 * @param [out] producedDate        Buffer to hold the date.
 * @param [in]  producedDate_space  Length of the buffer in bytes.
 * @param [out] producedDateFormat  Format of the date returned.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL, no response has been processed, or
 *          an output parameter is NULL.
 * @return  BUFFER_E when the buffer is too small for the date.
 */
int wolfSSL_get_ocsp_producedDate(
    WOLFSSL *ssl,
    byte *producedDate,
    size_t producedDate_space,
    int *producedDateFormat)
{
    int ret = 0;

    /* Validate parameter. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* No response has been processed when no date format was recorded. */
    else if ((ssl->ocspProducedDateFormat != ASN_UTC_TIME) &&
            (ssl->ocspProducedDateFormat != ASN_GENERALIZED_TIME)) {
        ret = BAD_FUNC_ARG;
    }
    else if ((producedDate == NULL) || (producedDateFormat == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (XSTRLEN((char *)ssl->ocspProducedDate) >= producedDate_space) {
        ret = BUFFER_E;
    }
    else {
        XSTRNCPY((char *)producedDate, (const char *)ssl->ocspProducedDate,
            producedDate_space);
        *producedDateFormat = ssl->ocspProducedDateFormat;
    }

    return ret;
}

/* Get the date the last OCSP response was produced as a broken-down time.
 *
 * @param [in]  ssl          SSL/TLS object.
 * @param [out] produced_tm  Broken-down time to fill in.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL, no response has been processed, or
 *          produced_tm is NULL.
 * @return  ASN_PARSE_E when the date cannot be parsed.
 */
int wolfSSL_get_ocsp_producedDate_tm(WOLFSSL *ssl, struct tm *produced_tm)
{
    int ret = 0;
    int idx = 0;

    /* Validate parameter. */
    if (ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* No response has been processed when no date format was recorded. */
    else if ((ssl->ocspProducedDateFormat != ASN_UTC_TIME) &&
            (ssl->ocspProducedDateFormat != ASN_GENERALIZED_TIME)) {
        ret = BAD_FUNC_ARG;
    }
    else if (produced_tm == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else if (!ExtractDate(ssl->ocspProducedDate,
            (unsigned char)ssl->ocspProducedDateFormat, produced_tm, &idx,
            MAX_DATE_SIZE)) {
        ret = ASN_PARSE_E;
    }

    return ret;
}
#endif /* !NO_ASN_TIME */
#endif /* HAVE_OCSP */

#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST

/* Ask for an OCSP response to be stapled to the handshake.
 *
 * @param [in, out] ssl          SSL/TLS object.
 * @param [in]      status_type  Type of status request.
 * @param [in]      options      Options to apply.
 * @return  Result of adding the extension.
 * @return  BAD_FUNC_ARG when ssl is NULL or the object is not a client.
 */
int wolfSSL_UseOCSPStapling(WOLFSSL* ssl, byte status_type, byte options)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_UseOCSPStapling");

    if ((ssl == NULL) || (ssl->options.side != WOLFSSL_CLIENT_END)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = TLSX_UseCertificateStatusRequest(&ssl->extensions, status_type,
            options, NULL, ssl->heap, ssl->devId);
    }

    return ret;
}


/* Ask for an OCSP response to be stapled to handshakes.
 *
 * @param [in, out] ctx          SSL/TLS context.
 * @param [in]      status_type  Type of status request.
 * @param [in]      options      Options to apply.
 * @return  Result of adding the extension.
 * @return  BAD_FUNC_ARG when ctx is NULL or the context is not a client.
 */
int wolfSSL_CTX_UseOCSPStapling(WOLFSSL_CTX* ctx, byte status_type,
                                                                   byte options)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_CTX_UseOCSPStapling");

    if ((ctx == NULL) || (ctx->method->side != WOLFSSL_CLIENT_END)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = TLSX_UseCertificateStatusRequest(&ctx->extensions, status_type,
            options, NULL, ctx->heap, ctx->devId);
    }

    return ret;
}

#endif /* HAVE_CERTIFICATE_STATUS_REQUEST */

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2

/* Ask for version 2 OCSP stapling on the handshake.
 *
 * @param [in, out] ssl          SSL/TLS object.
 * @param [in]      status_type  Type of status request.
 * @param [in]      options      Options to apply.
 * @return  Result of adding the extension.
 * @return  BAD_FUNC_ARG when ssl is NULL or the object is not a client.
 */
int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl, byte status_type, byte options)
{
    int ret;

    if ((ssl == NULL) || (ssl->options.side != WOLFSSL_CLIENT_END)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = TLSX_UseCertificateStatusRequestV2(&ssl->extensions, status_type,
            options, ssl->heap, ssl->devId);
    }

    return ret;
}


/* Ask for version 2 OCSP stapling on handshakes.
 *
 * @param [in, out] ctx          SSL/TLS context.
 * @param [in]      status_type  Type of status request.
 * @param [in]      options      Options to apply.
 * @return  Result of adding the extension.
 * @return  BAD_FUNC_ARG when ctx is NULL or the context is not a client.
 */
int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx, byte status_type,
                                                                   byte options)
{
    int ret;

    if ((ctx == NULL) || (ctx->method->side != WOLFSSL_CLIENT_END)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = TLSX_UseCertificateStatusRequestV2(&ctx->extensions, status_type,
            options, ctx->heap, ctx->devId);
    }

    return ret;
}

#endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */
#endif /* !NO_TLS && !NO_WOLFSSL_CLIENT */

#ifdef OPENSSL_EXTRA
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
/* Ask for a certificate status of the given type.
 *
 * @param [in, out] s     SSL/TLS object.
 * @param [in]      type  Status request type. Only
 *                        WOLFSSL_TLSEXT_STATUSTYPE_ocsp is supported.
 * @return  Result of adding the extension.
 * @return  BAD_FUNC_ARG when s is NULL.
 * @return  WOLFSSL_FAILURE when the type is not OCSP.
 */
long wolfSSL_set_tlsext_status_type(WOLFSSL *s, int type)
{
    long ret;

    WOLFSSL_ENTER("wolfSSL_set_tlsext_status_type");

    if (s == NULL) {
        ret = BAD_FUNC_ARG;
    }
    else if (type != WOLFSSL_TLSEXT_STATUSTYPE_ocsp) {
        WOLFSSL_MSG(
       "SSL_set_tlsext_status_type only supports TLSEXT_STATUSTYPE_ocsp type.");
        ret = WOLFSSL_FAILURE;
    }
    else {
        ret = (long)TLSX_UseCertificateStatusRequest(&s->extensions,
            (byte)type, 0, s, s->heap, s->devId);
    }

    return ret;
}

/* Get the type of certificate status requested.
 *
 * @param [in] s  SSL/TLS object.
 * @return  WOLFSSL_TLSEXT_STATUSTYPE_ocsp when a status was requested.
 * @return  WOLFSSL_FATAL_ERROR when s is NULL or no status was requested.
 */
long wolfSSL_get_tlsext_status_type(WOLFSSL *s)
{
    long ret;

    if (s == NULL) {
        ret = WOLFSSL_FATAL_ERROR;
    }
    else {
        TLSX* extension = TLSX_Find(s->extensions, TLSX_STATUS_REQUEST);

        if (extension != NULL) {
            ret = WOLFSSL_TLSEXT_STATUSTYPE_ocsp;
        }
        else {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    return ret;
}
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST */
#endif /* OPENSSL_EXTRA */

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
        defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
/* Get the callback that supplies the certificate status.
 *
 * @param [in]  ctx  SSL/TLS context.
 * @param [out] cb   Receives the status callback.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when a parameter is NULL or stapling is not set up.
 */
int wolfSSL_CTX_get_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb* cb)
{
    int ret = WOLFSSL_SUCCESS;

    if ((ctx == NULL) || (ctx->cm == NULL) || (cb == NULL)) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        #if !defined(NO_WOLFSSL_SERVER) && \
            (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
             defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
        if (ctx->cm->ocsp_stapling == NULL) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            *cb = ctx->cm->ocsp_stapling->statusCb;
        }
        #else
        *cb = NULL;
        #endif
    }

    return ret;
}

/* Set the callback that supplies the certificate status.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @param [in]      cb   Callback to call. NULL to clear.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx is NULL or stapling cannot be turned on.
 */
int wolfSSL_CTX_set_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb cb)
{
    int ret = WOLFSSL_SUCCESS;

    if ((ctx == NULL) || (ctx->cm == NULL)) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        #if !defined(NO_WOLFSSL_SERVER) && \
            (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
             defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
        /* Ensure stapling is on for callback to be used. */
        wolfSSL_CTX_EnableOCSPStapling(ctx);

        if (ctx->cm->ocsp_stapling == NULL) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            ctx->cm->ocsp_stapling->statusCb = cb;
        }
        #else
        (void)cb;
        #endif
    }

    return ret;
}

/* Set the argument passed to the certificate status callback.
 *
 * @param [in, out] ctx  SSL/TLS context.
 * @param [in]      arg  Argument to pass to the callback.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx is NULL or stapling cannot be turned on.
 */
long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg)
{
    long ret = WOLFSSL_SUCCESS;

    if ((ctx == NULL) || (ctx->cm == NULL)) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        #if !defined(NO_WOLFSSL_SERVER) && \
            (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
             defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
        /* Ensure stapling is on for callback to be used. */
        wolfSSL_CTX_EnableOCSPStapling(ctx);

        if (ctx->cm->ocsp_stapling == NULL) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            ctx->cm->ocsp_stapling->statusCbArg = arg;
        }
        #else
        (void)arg;
        #endif
    }

    return ret;
}

/* Get the OCSP response this side has staged to staple.
 *
 * The response is the one set by wolfSSL_set_tlsext_status_ocsp_resp(), not
 * one received from the peer. It stays owned by the SSL/TLS object, so the
 * caller must not free it.
 *
 * @param [in]  ssl   SSL/TLS object.
 * @param [out] resp  Receives the stapled response, or NULL when there is
 *                    none. Written only when both parameters are non-NULL,
 *                    so a caller that passes a NULL ssl is left with
 *                    whatever it had - check the return value before reading
 *                    it.
 * @return  Length of the response, which is zero when there is none or when
 *          a parameter is NULL.
 */
long wolfSSL_get_tlsext_status_ocsp_resp(WOLFSSL *ssl, unsigned char **resp)
{
    long ret = 0;

    if ((ssl != NULL) && (resp != NULL)) {
        *resp = ssl->ocspCsrResp[0].buffer;
        ret = (long)ssl->ocspCsrResp[0].length;
    }

    return ret;
}

/* Set the OCSP response to staple for the first certificate.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      resp  Response to store. Ownership is taken on success
 *                        only - when this call fails the caller still owns
 *                        it. The stored response is later released with
 *                        XFREE(resp, NULL, 0), so it must be allocated to
 *                        match.
 * @param [in]      len   Length of the response in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl is NULL or the response and length
 *          disagree.
 */
long wolfSSL_set_tlsext_status_ocsp_resp(WOLFSSL *ssl, unsigned char *resp,
    int len)
{
    return wolfSSL_set_tlsext_status_ocsp_resp_multi(ssl, resp, len, 0);
}

/* Set the OCSP response to staple for one certificate of the chain.
 *
 * @param [in, out] ssl   SSL/TLS object.
 * @param [in]      resp  Response to store. Ownership is taken on success
 *                        only - when this call fails the caller still owns
 *                        it. The stored response is later released with
 *                        XFREE(resp, NULL, 0), so it must be allocated to
 *                        match.
 * @param [in]      len   Length of the response in bytes.
 * @param [in]      idx   Index of the certificate the response is for.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl is NULL, idx is out of range, or the
 *          response and length disagree.
 */
int wolfSSL_set_tlsext_status_ocsp_resp_multi(WOLFSSL* ssl, unsigned char *resp,
        int len, word32 idx)
{
    int ret = WOLFSSL_SUCCESS;

    if ((ssl == NULL) || (idx >= XELEM_CNT(ssl->ocspCsrResp)) || (len < 0)) {
        ret = WOLFSSL_FAILURE;
    }
    /* A response and a length must be supplied together. */
    else if (!((resp == NULL) ^ (len > 0))) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        XFREE(ssl->ocspCsrResp[idx].buffer, NULL, 0);
        ssl->ocspCsrResp[idx].buffer = resp;
        ssl->ocspCsrResp[idx].length = (word32)len;
    }

    return ret;
}

#ifndef NO_WOLFSSL_SERVER
/* Set the callback that verifies a stapled OCSP response.
 *
 * @param [in, out] ctx    SSL/TLS context.
 * @param [in]      cb     Callback to call. NULL to clear.
 * @param [in]      cbArg  Argument to pass to the callback.
 */
void wolfSSL_CTX_set_ocsp_status_verify_cb(WOLFSSL_CTX* ctx,
        ocspVerifyStatusCb cb, void* cbArg)
{
    if (ctx != NULL) {
        ctx->ocspStatusVerifyCb = cb;
        ctx->ocspStatusVerifyCbArg = cbArg;
    }
}
#endif /* NO_WOLFSSL_SERVER */
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST ||
        * HAVE_CERTIFICATE_STATUS_REQUEST_V2 */

#endif /* !NO_CERTS */

#ifdef OPENSSL_EXTRA

/* Split an OCSP responder URL into its parts.
 *
 * URL is of the form: [http[s]://][userinfo@]host[:port][/path][?query][#frag]
 * Host, port and path are allocated and must be freed by the caller.
 *
 * This follows OpenSSL's OCSP_parse_url(), which is OSSL_HTTP_parse_url() with
 * the userinfo, port number, query and fragment outputs discarded. The
 * behaviour that follows from that, and which differs from a naive reading of
 * RFC 3986, is deliberate:
 *  - The scheme is matched case sensitively and may be omitted entirely; a URL
 *    with no "://" is parsed as http with the default port.
 *  - Userinfo runs to the FIRST '@' of the authority and is discarded, so the
 *    host is the text after it. That is not the name that reads first in the
 *    URL: "http://ocsp.example.com@attacker.example/" is a request to
 *    attacker.example. These URLs come from a certificate's AIA extension, so
 *    whoever issued the certificate chooses that text - anything that logs,
 *    pins or allow-lists a responder must use the host returned here rather
 *    than the URL it came from.
 *  - An IPv6 literal keeps its brackets, so the host of "http://[::1]/p" is
 *    "[::1]". Note wolfIO_DecodeUrl() strips them.
 *  - The port is returned as written, so "http://host:00080/p" reports
 *    "00080". An explicit ":0" is reported as the scheme's default port.
 *  - The query stays with the path and the fragment is dropped, matching what
 *    OpenSSL does when neither is asked for.
 *
 * Two checks are kept that OpenSSL does not make, both cases where it is
 * silent rather than permissive: a CR or LF anywhere in the URL is rejected,
 * as it would split a request built from these parts into extra header lines,
 * and an empty host is rejected rather than returned as "".
 *
 * A malformed URL or a failed allocation leaves host, port and path NULL. A
 * NULL parameter, though, is reported before any of them is written, so on
 * that failure they hold whatever the caller left in them.
 *
 * @param [in]  url   URL of OCSP responder.
 * @param [out] host  Host name of responder, brackets included when it is an
 *                    IPv6 literal.
 * @param [out] port  Port of responder. "80" or "443" when not in URL.
 * @param [out] path  Path of responder. "/" when not in URL.
 * @param [out] ssl   1 when scheme is https, 0 otherwise.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when a parameter is NULL, the URL is malformed or
 *          dynamic memory allocation fails.
 */
int wolfSSL_OCSP_parse_url(const char* url, char** host, char** port,
        char** path, int* ssl)
{
    const char* c;
    const char* p;          /* cursor into url */
    const char* authEnd;    /* end of the authority */
    const char* hostStart;
    const char* hostEnd;
    const char* uport;      /* port digits in url, NULL when not given */
    const char* portEnd;
    const char* upath;      /* path in url */
    const char* pathEnd;    /* end of the path, before any fragment */
    const char* query;
    int hostLen;
    int pathLen;
    word32 portNum = 0;
    int ret;

    WOLFSSL_ENTER("wolfSSL_OCSP_parse_url");

    /* Skip the cleanup below: nothing has been assigned yet, and the out
     * parameters cannot all be dereferenced when one of them is the NULL
     * one. None of them is written on this path, not even those that were
     * passed in - see the note above the function. */
    if ((url == NULL) || (host == NULL) || (port == NULL) || (path == NULL) ||
            (ssl == NULL)) {
        ret = WOLFSSL_FAILURE;
        goto done;
    }

    *host = NULL;
    *port = NULL;
    *path = NULL;
    *ssl = 0;

    /* CR/LF in the parsed out host or path would split a request built from
     * them into extra header lines. Not a check OpenSSL makes. */
    for (c = url; *c != '\0'; c++) {
        if ((*c == '\r') || (*c == '\n')) {
            WOLFSSL_MSG("CR/LF in URL");
            goto err;
        }
    }

    /* Optional "<scheme>://" prefix. Only http and https are understood, and
     * only in lower case, as OpenSSL compares the scheme with strcmp(). */
    p = XSTRSTR(url, "://");
    if (p == NULL) {
        /* No scheme at all is accepted and parsed as http. */
        p = url;
    }
    else {
        if (p == url) {
            WOLFSSL_MSG("Empty URL scheme");
            goto err;
        }
        if (((p - url) == 5) && (XSTRNCMP(url, "https", 5) == 0)) {
            *ssl = 1;
        }
        else if (((p - url) != 4) || (XSTRNCMP(url, "http", 4) != 0)) {
            WOLFSSL_MSG("URL scheme is not http or https");
            goto err;
        }
        p += 3;
    }

    /* The authority ends at the first '/', '?' or '#'. */
    for (authEnd = p; *authEnd != '\0'; authEnd++) {
        if ((*authEnd == '/') || (*authEnd == '?') || (*authEnd == '#')) {
            break;
        }
    }

    /* Userinfo, when present, runs to the first '@' of the authority and is
     * discarded - the host is what follows it. See the warning above. */
    hostStart = p;
    for (c = p; c < authEnd; c++) {
        if (*c == '@') {
            hostStart = c + 1;
            break;
        }
    }

    /* An IPv6 literal is bracketed and holds colons of its own, so the host
     * runs to the ']' and the brackets are part of it. The search is not
     * bounded by the authority, matching OpenSSL. */
    if (*hostStart == '[') {
        for (c = hostStart + 1; (*c != '\0') && (*c != ']'); c++) {
            /* Find the end of the literal. */
        }
        if (*c == '\0') {
            WOLFSSL_MSG("Unterminated IPv6 literal in URL");
            goto err;
        }
        hostEnd = c + 1;
    }
    else {
        for (c = hostStart; *c != '\0'; c++) {
            if ((*c == ':') || (*c == '/') || (*c == '?') || (*c == '#')) {
                break;
            }
        }
        hostEnd = c;
    }
    p = hostEnd;

    /* Optional port, which must be digits and in range. Anything else left
     * between the host and the path is caught by the path check below. */
    uport = NULL;
    portEnd = NULL;
    if (*p == ':') {
        uport = ++p;
        for (portEnd = uport; (*portEnd >= '0') && (*portEnd <= '9');
                portEnd++) {
            portNum = (portNum * 10) + (word32)(*portEnd - '0');
            if (portNum > WOLFSSL_MAX_16BIT) {
                WOLFSSL_MSG("Port out of range in URL");
                goto err;
            }
        }
        if (portEnd == uport) {
            WOLFSSL_MSG("No port after ':' in URL");
            goto err;
        }
        p = portEnd;
    }

    /* Whatever is left must be a path, a query or a fragment. */
    upath = p;
    if ((*upath != '\0') && (*upath != '/') && (*upath != '?') &&
            (*upath != '#')) {
        WOLFSSL_MSG("Unexpected character after authority in URL");
        goto err;
    }

    /* The query stays with the path; the fragment is dropped. OpenSSL looks
     * for the fragment from the query onwards, so a '#' before the query is
     * left in the path. */
    query = upath;
    for (c = upath; *c != '\0'; c++) {
        if (*c == '?') {
            query = c;
            break;
        }
    }
    pathEnd = upath + XSTRLEN(upath);
    for (c = query; *c != '\0'; c++) {
        if (*c == '#') {
            pathEnd = c;
            break;
        }
    }

    /* The length is computed rather than passed as -1 because CopyString()
     * treats a length of zero as "copy the rest of the string", which would
     * turn an empty host into the remainder of the URL. */
    hostLen = (int)(hostEnd - hostStart);
    if (hostLen == 0) {
        /* OpenSSL returns an empty host here; refuse it instead, as nothing
         * can be fetched from it. */
        WOLFSSL_MSG("No host in URL");
        goto err;
    }
    *host = CopyString(hostStart, hostLen, NULL, DYNAMIC_TYPE_OPENSSL);
    if (*host == NULL) {
        goto err;
    }

    if ((uport == NULL) || ((portEnd - uport == 1) && (*uport == '0'))) {
        /* No port, or the ":0" OpenSSL maps to the scheme's default. */
        *port = CopyString((*ssl) ? "443" : "80", -1, NULL,
                           DYNAMIC_TYPE_OPENSSL);
    }
    else {
        /* Returned as written - a padded port is not canonicalized. */
        *port = CopyString(uport, (int)(portEnd - uport), NULL,
                           DYNAMIC_TYPE_OPENSSL);
    }
    if (*port == NULL) {
        goto err;
    }

    pathLen = (int)(pathEnd - upath);
    if ((pathLen > 0) && (*upath == '/')) {
        *path = CopyString(upath, pathLen, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    else {
        /* No path, or one that starts with the query: prepend the '/' that
         * the request line needs, as OpenSSL does. */
        *path = (char*)XMALLOC((size_t)pathLen + 2, NULL,
                               DYNAMIC_TYPE_OPENSSL);
        if (*path != NULL) {
            (*path)[0] = '/';
            if (pathLen > 0) {
                XMEMCPY(*path + 1, upath, (size_t)pathLen);
            }
            (*path)[pathLen + 1] = '\0';
        }
    }
    if (*path == NULL) {
        goto err;
    }

    ret = WOLFSSL_SUCCESS;
    goto done;

err:
    ret = WOLFSSL_FAILURE;
    /* Release anything parsed out so nothing is returned half-filled. The
     * scheme flag is set before the authority is validated, so it is reset
     * here too. */
    XFREE(*host, NULL, DYNAMIC_TYPE_OPENSSL);
    *host = NULL;
    XFREE(*port, NULL, DYNAMIC_TYPE_OPENSSL);
    *port = NULL;
    XFREE(*path, NULL, DYNAMIC_TYPE_OPENSSL);
    *path = NULL;
    *ssl = 0;

done:
    return ret;
}

#endif /* OPENSSL_EXTRA */

#endif /* !WOLFSSL_SSL_API_CRL_OCSP_INCLUDED */

