/* ssl_api_crl_ocsp.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if !defined(WOLFSSL_SSL_API_CRL_OCSP_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_api_crl_ocsp.c is not compiled separately from ssl.c
    #endif
#else

#ifndef NO_CERTS

#ifdef HAVE_CRL

int wolfSSL_CTX_LoadCRLBuffer(WOLFSSL_CTX* ctx, const unsigned char* buff,
                              long sz, int type)
{
    WOLFSSL_ENTER("wolfSSL_CTX_LoadCRLBuffer");

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return wolfSSL_CertManagerLoadCRLBuffer(ctx->cm, buff, sz, type);
}


int wolfSSL_LoadCRLBuffer(WOLFSSL* ssl, const unsigned char* buff,
                          long sz, int type)
{
    WOLFSSL_ENTER("wolfSSL_LoadCRLBuffer");

    if (ssl == NULL || ssl->ctx == NULL)
        return BAD_FUNC_ARG;

    SSL_CM_WARNING(ssl);
    return wolfSSL_CertManagerLoadCRLBuffer(SSL_CM(ssl), buff, sz, type);
}

int wolfSSL_EnableCRL(WOLFSSL* ssl, int options)
{
    WOLFSSL_ENTER("wolfSSL_EnableCRL");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerEnableCRL(SSL_CM(ssl), options);
    }
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_DisableCRL(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_DisableCRL");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerDisableCRL(SSL_CM(ssl));
    }
    else
        return BAD_FUNC_ARG;
}

#ifndef NO_FILESYSTEM
int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type, int monitor)
{
    WOLFSSL_ENTER("wolfSSL_LoadCRL");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerLoadCRL(SSL_CM(ssl), path, type, monitor);
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_LoadCRLFile(WOLFSSL* ssl, const char* file, int type)
{
    WOLFSSL_ENTER("wolfSSL_LoadCRLFile");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerLoadCRLFile(SSL_CM(ssl), file, type);
    }
    else
        return BAD_FUNC_ARG;
}
#endif

int wolfSSL_SetCRL_Cb(WOLFSSL* ssl, CbMissingCRL cb)
{
    WOLFSSL_ENTER("wolfSSL_SetCRL_Cb");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerSetCRL_Cb(SSL_CM(ssl), cb);
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_SetCRL_ErrorCb(WOLFSSL* ssl, crlErrorCb cb, void* ctx)
{
    WOLFSSL_ENTER("wolfSSL_SetCRL_Cb");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerSetCRL_ErrorCb(SSL_CM(ssl), cb, ctx);
    }
    else
        return BAD_FUNC_ARG;
}

#ifdef HAVE_CRL_IO
int wolfSSL_SetCRL_IOCb(WOLFSSL* ssl, CbCrlIO cb)
{
    WOLFSSL_ENTER("wolfSSL_SetCRL_Cb");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerSetCRL_IOCb(SSL_CM(ssl), cb);
    }
    else
        return BAD_FUNC_ARG;
}
#endif

int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options)
{
    WOLFSSL_ENTER("wolfSSL_CTX_EnableCRL");
    if (ctx)
        return wolfSSL_CertManagerEnableCRL(ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_DisableCRL");
    if (ctx)
        return wolfSSL_CertManagerDisableCRL(ctx->cm);
    else
        return BAD_FUNC_ARG;
}


#ifndef NO_FILESYSTEM
int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX* ctx, const char* path,
                        int type, int monitor)
{
    WOLFSSL_ENTER("wolfSSL_CTX_LoadCRL");
    if (ctx)
        return wolfSSL_CertManagerLoadCRL(ctx->cm, path, type, monitor);
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_LoadCRLFile(WOLFSSL_CTX* ctx, const char* file,
                        int type)
{
    WOLFSSL_ENTER("wolfSSL_CTX_LoadCRL");
    if (ctx)
        return wolfSSL_CertManagerLoadCRLFile(ctx->cm, file, type);
    else
        return BAD_FUNC_ARG;
}
#endif


int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX* ctx, CbMissingCRL cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetCRL_Cb");
    if (ctx)
        return wolfSSL_CertManagerSetCRL_Cb(ctx->cm, cb);
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_SetCRL_ErrorCb(WOLFSSL_CTX* ctx, crlErrorCb cb, void* cbCtx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetCRL_ErrorCb");
    if (ctx)
        return wolfSSL_CertManagerSetCRL_ErrorCb(ctx->cm, cb, cbCtx);
    else
        return BAD_FUNC_ARG;
}

#ifdef HAVE_CRL_IO
int wolfSSL_CTX_SetCRL_IOCb(WOLFSSL_CTX* ctx, CbCrlIO cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetCRL_IOCb");
    if (ctx)
        return wolfSSL_CertManagerSetCRL_IOCb(ctx->cm, cb);
    else
        return BAD_FUNC_ARG;
}
#endif

#endif /* HAVE_CRL */


#ifdef HAVE_OCSP
int wolfSSL_EnableOCSP(WOLFSSL* ssl, int options)
{
    WOLFSSL_ENTER("wolfSSL_EnableOCSP");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerEnableOCSP(SSL_CM(ssl), options);
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_DisableOCSP(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_DisableOCSP");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerDisableOCSP(SSL_CM(ssl));
    }
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_EnableOCSPStapling(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_EnableOCSPStapling");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerEnableOCSPStapling(SSL_CM(ssl));
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_DisableOCSPStapling(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_DisableOCSPStapling");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerDisableOCSPStapling(SSL_CM(ssl));
    }
    else
        return BAD_FUNC_ARG;
}
int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url)
{
    WOLFSSL_ENTER("wolfSSL_SetOCSP_OverrideURL");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        return wolfSSL_CertManagerSetOCSPOverrideURL(SSL_CM(ssl), url);
    }
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_SetOCSP_Cb(WOLFSSL* ssl,
                        CbOCSPIO ioCb, CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    WOLFSSL_ENTER("wolfSSL_SetOCSP_Cb");
    if (ssl) {
        SSL_CM_WARNING(ssl);
        ssl->ocspIOCtx = ioCbCtx; /* use SSL specific ioCbCtx */
        return wolfSSL_CertManagerSetOCSP_Cb(SSL_CM(ssl),
                                             ioCb, respFreeCb, NULL);
    }
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX* ctx, int options)
{
    WOLFSSL_ENTER("wolfSSL_CTX_EnableOCSP");
    if (ctx)
        return wolfSSL_CertManagerEnableOCSP(ctx->cm, options);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_DisableOCSP");
    if (ctx)
        return wolfSSL_CertManagerDisableOCSP(ctx->cm);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX* ctx, const char* url)
{
    WOLFSSL_ENTER("wolfSSL_SetOCSP_OverrideURL");
    if (ctx)
        return wolfSSL_CertManagerSetOCSPOverrideURL(ctx->cm, url);
    else
        return BAD_FUNC_ARG;
}


int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX* ctx, CbOCSPIO ioCb,
                           CbOCSPRespFree respFreeCb, void* ioCbCtx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_SetOCSP_Cb");
    if (ctx)
        return wolfSSL_CertManagerSetOCSP_Cb(ctx->cm, ioCb,
                                             respFreeCb, ioCbCtx);
    else
        return BAD_FUNC_ARG;
}

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_EnableOCSPStapling");
    if (ctx)
        return wolfSSL_CertManagerEnableOCSPStapling(ctx->cm);
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_DisableOCSPStapling(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_DisableOCSPStapling");
    if (ctx)
        return wolfSSL_CertManagerDisableOCSPStapling(ctx->cm);
    else
        return BAD_FUNC_ARG;
}
int wolfSSL_CTX_EnableOCSPMustStaple(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_EnableOCSPMustStaple");
    if (ctx)
        return wolfSSL_CertManagerEnableOCSPMustStaple(ctx->cm);
    else
        return BAD_FUNC_ARG;
}

int wolfSSL_CTX_DisableOCSPMustStaple(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_DisableOCSPMustStaple");
    if (ctx)
        return wolfSSL_CertManagerDisableOCSPMustStaple(ctx->cm);
    else
        return BAD_FUNC_ARG;
}
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST || \
        * HAVE_CERTIFICATE_STATUS_REQUEST_V2 */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
/* Not an OpenSSL API. */
int wolfSSL_get_ocsp_response(WOLFSSL* ssl, byte** response)
{
    *response = ssl->ocspCsrResp[0].buffer;
    return ssl->ocspCsrResp[0].length;
}

/* Not an OpenSSL API. */
char* wolfSSL_get_ocsp_url(WOLFSSL* ssl)
{
    return ssl->url;
}

/* Not an OpenSSL API. */
int wolfSSL_set_ocsp_url(WOLFSSL* ssl, char* url)
{
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    ssl->url = url;
    return WOLFSSL_SUCCESS;
}
#endif /* OPENSSL_ALL || WOLFSSL_NGINX  || WOLFSSL_HAPROXY */

#if !defined(NO_ASN_TIME)
int wolfSSL_get_ocsp_producedDate(
    WOLFSSL *ssl,
    byte *producedDate,
    size_t producedDate_space,
    int *producedDateFormat)
{
    if ((ssl->ocspProducedDateFormat != ASN_UTC_TIME) &&
        (ssl->ocspProducedDateFormat != ASN_GENERALIZED_TIME))
        return BAD_FUNC_ARG;

    if ((producedDate == NULL) || (producedDateFormat == NULL))
        return BAD_FUNC_ARG;

    if (XSTRLEN((char *)ssl->ocspProducedDate) >= producedDate_space)
        return BUFFER_E;

    XSTRNCPY((char *)producedDate, (const char *)ssl->ocspProducedDate,
        producedDate_space);
    *producedDateFormat = ssl->ocspProducedDateFormat;

    return 0;
}

int wolfSSL_get_ocsp_producedDate_tm(WOLFSSL *ssl, struct tm *produced_tm) {
    int idx = 0;

    if ((ssl->ocspProducedDateFormat != ASN_UTC_TIME) &&
        (ssl->ocspProducedDateFormat != ASN_GENERALIZED_TIME))
        return BAD_FUNC_ARG;

    if (produced_tm == NULL)
        return BAD_FUNC_ARG;

    if (ExtractDate(ssl->ocspProducedDate,
            (unsigned char)ssl->ocspProducedDateFormat, produced_tm, &idx,
            MAX_DATE_SZ))
        return 0;
    else
        return ASN_PARSE_E;
}
#endif /* !NO_ASN_TIME */
#endif /* HAVE_OCSP */

#if !defined(NO_TLS) && !defined(NO_WOLFSSL_CLIENT)
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST

int wolfSSL_UseOCSPStapling(WOLFSSL* ssl, byte status_type, byte options)
{
    WOLFSSL_ENTER("wolfSSL_UseOCSPStapling");

    if (ssl == NULL || ssl->options.side != WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

    return TLSX_UseCertificateStatusRequest(&ssl->extensions, status_type,
                                          options, NULL, ssl->heap, ssl->devId);
}


int wolfSSL_CTX_UseOCSPStapling(WOLFSSL_CTX* ctx, byte status_type,
                                                                   byte options)
{
    WOLFSSL_ENTER("wolfSSL_CTX_UseOCSPStapling");

    if (ctx == NULL || ctx->method->side != WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

    return TLSX_UseCertificateStatusRequest(&ctx->extensions, status_type,
                                          options, NULL, ctx->heap, ctx->devId);
}

#endif /* HAVE_CERTIFICATE_STATUS_REQUEST */

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2

int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl, byte status_type, byte options)
{
    if (ssl == NULL || ssl->options.side != WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

    return TLSX_UseCertificateStatusRequestV2(&ssl->extensions, status_type,
                                                options, ssl->heap, ssl->devId);
}


int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx, byte status_type,
                                                                   byte options)
{
    if (ctx == NULL || ctx->method->side != WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

    return TLSX_UseCertificateStatusRequestV2(&ctx->extensions, status_type,
                                                options, ctx->heap, ctx->devId);
}

#endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */
#endif /* !NO_TLS && !NO_WOLFSSL_CLIENT */

#ifdef OPENSSL_EXTRA
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
long wolfSSL_set_tlsext_status_type(WOLFSSL *s, int type)
{
    WOLFSSL_ENTER("wolfSSL_set_tlsext_status_type");

    if (s == NULL){
        return BAD_FUNC_ARG;
    }

    if (type == WOLFSSL_TLSEXT_STATUSTYPE_ocsp){
        int r = TLSX_UseCertificateStatusRequest(&s->extensions, (byte)type, 0,
            s, s->heap, s->devId);
        return (long)r;
    } else {
        WOLFSSL_MSG(
       "SSL_set_tlsext_status_type only supports TLSEXT_STATUSTYPE_ocsp type.");
        return WOLFSSL_FAILURE;
    }

}

long wolfSSL_get_tlsext_status_type(WOLFSSL *s)
{
    TLSX* extension;

    if (s == NULL)
        return WOLFSSL_FATAL_ERROR;
    extension = TLSX_Find(s->extensions, TLSX_STATUS_REQUEST);
    return (extension != NULL) ? WOLFSSL_TLSEXT_STATUSTYPE_ocsp :
                                 WOLFSSL_FATAL_ERROR;
}
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST */
#endif /* OPENSSL_EXTRA */

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
        defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
int wolfSSL_CTX_get_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb* cb)
{
    if (ctx == NULL || ctx->cm == NULL || cb == NULL)
        return WOLFSSL_FAILURE;

#if !defined(NO_WOLFSSL_SERVER) && (defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
                               || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
    if (ctx->cm->ocsp_stapling == NULL)
        return WOLFSSL_FAILURE;

    *cb = ctx->cm->ocsp_stapling->statusCb;
#else
    (void)cb;
    *cb = NULL;
#endif

    return WOLFSSL_SUCCESS;

}

int wolfSSL_CTX_set_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb cb)
{
    if (ctx == NULL || ctx->cm == NULL)
        return WOLFSSL_FAILURE;

#if !defined(NO_WOLFSSL_SERVER) && (defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
                               || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
    /* Ensure stapling is on for callback to be used. */
    wolfSSL_CTX_EnableOCSPStapling(ctx);

    if (ctx->cm->ocsp_stapling == NULL)
        return WOLFSSL_FAILURE;

    ctx->cm->ocsp_stapling->statusCb = cb;
#else
    (void)cb;
#endif

    return WOLFSSL_SUCCESS;
}

long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg)
{
    if (ctx == NULL || ctx->cm == NULL)
        return WOLFSSL_FAILURE;

#if !defined(NO_WOLFSSL_SERVER) && (defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
                               || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))
    /* Ensure stapling is on for callback to be used. */
    wolfSSL_CTX_EnableOCSPStapling(ctx);

    if (ctx->cm->ocsp_stapling == NULL)
        return WOLFSSL_FAILURE;

    ctx->cm->ocsp_stapling->statusCbArg = arg;
#else
    (void)arg;
#endif

    return WOLFSSL_SUCCESS;
}

long wolfSSL_get_tlsext_status_ocsp_resp(WOLFSSL *ssl, unsigned char **resp)
{
    if (ssl == NULL || resp == NULL)
        return 0;

    *resp = ssl->ocspCsrResp[0].buffer;
    return (long)ssl->ocspCsrResp[0].length;
}

long wolfSSL_set_tlsext_status_ocsp_resp(WOLFSSL *ssl, unsigned char *resp,
    int len)
{
    return wolfSSL_set_tlsext_status_ocsp_resp_multi(ssl, resp, len, 0);
}

int wolfSSL_set_tlsext_status_ocsp_resp_multi(WOLFSSL* ssl, unsigned char *resp,
        int len, word32 idx)
{
    if (ssl == NULL || idx >= XELEM_CNT(ssl->ocspCsrResp) || len < 0)
        return WOLFSSL_FAILURE;
    if (!((resp == NULL) ^ (len > 0)))
        return WOLFSSL_FAILURE;

    XFREE(ssl->ocspCsrResp[idx].buffer, NULL, 0);
    ssl->ocspCsrResp[idx].buffer = resp;
    ssl->ocspCsrResp[idx].length = (word32)len;

    return WOLFSSL_SUCCESS;
}

#ifndef NO_WOLFSSL_SERVER
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

#endif /* !WOLFSSL_SSL_API_CRL_OCSP_INCLUDED */

