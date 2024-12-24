/* x509_str.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if !defined(WOLFSSL_X509_STORE_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning x509_str.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef WOLFCRYPT_ONLY

#ifndef NO_CERTS

#ifdef OPENSSL_EXTRA
static int X509StoreGetIssuerEx(WOLFSSL_X509 **issuer,
                            WOLFSSL_STACK *certs, WOLFSSL_X509 *x);
static int X509StoreAddCa(WOLFSSL_X509_STORE* store,
                                          WOLFSSL_X509* x509, int type);
#endif

/* Based on OpenSSL default max depth */
#ifndef WOLFSSL_X509_STORE_DEFAULT_MAX_DEPTH
#define WOLFSSL_X509_STORE_DEFAULT_MAX_DEPTH 100
#endif

/******************************************************************************
 * START OF X509_STORE_CTX APIs
 *****************************************************************************/

/* This API is necessary outside of OPENSSL_EXTRA because it is used in
 * SetupStoreCtxCallback */
WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new_ex(void* heap)
{
    WOLFSSL_X509_STORE_CTX* ctx;
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_new_ex");

    ctx = (WOLFSSL_X509_STORE_CTX*)XMALLOC(sizeof(WOLFSSL_X509_STORE_CTX), heap,
                                    DYNAMIC_TYPE_X509_CTX);
    if (ctx != NULL) {
        XMEMSET(ctx, 0, sizeof(WOLFSSL_X509_STORE_CTX));
        ctx->heap = heap;
#ifdef OPENSSL_EXTRA
        if ((ctx->owned = wolfSSL_sk_X509_new_null()) == NULL) {
            XFREE(ctx, heap, DYNAMIC_TYPE_X509_CTX);
            ctx = NULL;
        }
        if (ctx != NULL &&
            wolfSSL_X509_STORE_CTX_init(ctx, NULL, NULL, NULL) !=
                WOLFSSL_SUCCESS) {
            wolfSSL_X509_STORE_CTX_free(ctx);
            ctx = NULL;
        }
#endif
    }

    return ctx;
}

/* This API is necessary outside of OPENSSL_EXTRA because it is used in
 * SetupStoreCtxCallback */
/* free's extra data */
void wolfSSL_X509_STORE_CTX_free(WOLFSSL_X509_STORE_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_free");
    if (ctx != NULL) {
#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
        wolfSSL_CRYPTO_cleanup_ex_data(&ctx->ex_data);
#endif

#ifdef OPENSSL_EXTRA
        XFREE(ctx->param, ctx->heap, DYNAMIC_TYPE_OPENSSL);
        ctx->param = NULL;

        if (ctx->chain != NULL) {
            wolfSSL_sk_X509_free(ctx->chain);
        }
        if (ctx->owned != NULL) {
            wolfSSL_sk_X509_pop_free(ctx->owned, NULL);
        }

        if (ctx->current_issuer != NULL) {
            wolfSSL_X509_free(ctx->current_issuer);
        }
#endif

        XFREE(ctx, ctx->heap, DYNAMIC_TYPE_X509_CTX);
    }
}

#ifdef OPENSSL_EXTRA

#if ((defined(SESSION_CERTS) && !defined(WOLFSSL_QT)) || \
      defined(WOLFSSL_SIGNER_DER_CERT))

/**
 * Find the issuing cert of the input cert. On a self-signed cert this
 * function will return an error.
 * @param issuer The issuer x509 struct is returned here
 * @param cm     The cert manager that is queried for the issuer
 * @param x      This cert's issuer will be queried in cm
 * @return       WOLFSSL_SUCCESS on success
 *               WOLFSSL_FAILURE on error
 */
static int x509GetIssuerFromCM(WOLFSSL_X509 **issuer, WOLFSSL_CERT_MANAGER* cm,
        WOLFSSL_X509 *x)
{
    Signer* ca = NULL;
#ifdef WOLFSSL_SMALL_STACK
    DecodedCert* cert = NULL;
#else
    DecodedCert  cert[1];
#endif

    if (cm == NULL || x == NULL || x->derCert == NULL) {
        WOLFSSL_MSG("No cert DER buffer or NULL cm. Defining "
                    "WOLFSSL_SIGNER_DER_CERT could solve the issue");
        return WOLFSSL_FAILURE;
    }

#ifdef WOLFSSL_SMALL_STACK
    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_DCERT);
    if (cert == NULL)
        return WOLFSSL_FAILURE;
#endif

    /* Use existing CA retrieval APIs that use DecodedCert. */
    InitDecodedCert(cert, x->derCert->buffer, x->derCert->length, cm->heap);
    if (ParseCertRelative(cert, CERT_TYPE, 0, NULL, NULL) == 0
            && !cert->selfSigned) {
    #ifndef NO_SKID
        if (cert->extAuthKeyIdSet)
            ca = GetCA(cm, cert->extAuthKeyId);
        if (ca == NULL)
            ca = GetCAByName(cm, cert->issuerHash);
    #else /* NO_SKID */
        ca = GetCA(cm, cert->issuerHash);
    #endif /* NO SKID */
    }
    FreeDecodedCert(cert);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
#endif

    if (ca == NULL)
        return WOLFSSL_FAILURE;

#ifdef WOLFSSL_SIGNER_DER_CERT
    /* populate issuer with Signer DER */
    if (wolfSSL_X509_d2i_ex(issuer, ca->derCert->buffer,
            ca->derCert->length, cm->heap) == NULL)
        return WOLFSSL_FAILURE;
#else
    /* Create an empty certificate as CA doesn't have a certificate. */
    *issuer = (WOLFSSL_X509 *)XMALLOC(sizeof(WOLFSSL_X509), 0,
        DYNAMIC_TYPE_OPENSSL);
    if (*issuer == NULL)
        return WOLFSSL_FAILURE;

    InitX509((*issuer), 1, NULL);
#endif

    return WOLFSSL_SUCCESS;
}
#endif /* SESSION_CERTS || WOLFSSL_SIGNER_DER_CERT */

WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new(void)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_new");
    return wolfSSL_X509_STORE_CTX_new_ex(NULL);
}

int wolfSSL_X509_STORE_CTX_init(WOLFSSL_X509_STORE_CTX* ctx,
     WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509,
     WOLF_STACK_OF(WOLFSSL_X509)* sk)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_init");

    if (ctx != NULL) {
        ctx->store = store;
        #ifndef WOLFSSL_X509_STORE_CERTS
        ctx->current_cert = x509;
        #else
        if(x509 != NULL){
            ctx->current_cert = wolfSSL_X509_d2i_ex(NULL,
                    x509->derCert->buffer,
                    x509->derCert->length,
                    x509->heap);
            if(ctx->current_cert == NULL)
                return WOLFSSL_FAILURE;
        } else
            ctx->current_cert = NULL;
        #endif

        ctx->ctxIntermediates = sk;
        if (ctx->chain != NULL) {
            wolfSSL_sk_X509_free(ctx->chain);
            ctx->chain = NULL;
        }
#ifdef SESSION_CERTS
        ctx->sesChain = NULL;
#endif
        ctx->domain = NULL;
#ifdef HAVE_EX_DATA
        XMEMSET(&ctx->ex_data, 0, sizeof(ctx->ex_data));
#endif
        ctx->userCtx = NULL;
        ctx->error = 0;
        ctx->error_depth = 0;
        ctx->discardSessionCerts = 0;

        if (ctx->param == NULL) {
            ctx->param = (WOLFSSL_X509_VERIFY_PARAM*)XMALLOC(
                           sizeof(WOLFSSL_X509_VERIFY_PARAM),
                           ctx->heap, DYNAMIC_TYPE_OPENSSL);
            if (ctx->param == NULL){
                WOLFSSL_MSG("wolfSSL_X509_STORE_CTX_init failed");
                return WOLFSSL_FAILURE;
            }
            XMEMSET(ctx->param, 0, sizeof(*ctx->param));
        }

        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}

/* Its recommended to use a full free -> init cycle of all the objects
 * because wolfSSL_X509_STORE_CTX_init may modify the store too which doesn't
 * get reset here. */
void wolfSSL_X509_STORE_CTX_cleanup(WOLFSSL_X509_STORE_CTX* ctx)
{
    if (ctx != NULL) {

        XFREE(ctx->param, ctx->heap, DYNAMIC_TYPE_OPENSSL);
        ctx->param = NULL;

        wolfSSL_X509_STORE_CTX_init(ctx, NULL, NULL, NULL);
    }
}


void wolfSSL_X509_STORE_CTX_trusted_stack(WOLFSSL_X509_STORE_CTX *ctx,
                                          WOLF_STACK_OF(WOLFSSL_X509) *sk)
{
    if (ctx != NULL) {
        ctx->setTrustedSk = sk;
    }
}


/* Returns corresponding X509 error from internal ASN error <e> */
int GetX509Error(int e)
{
    switch (e) {
        case WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E):
            return WOLFSSL_X509_V_ERR_CERT_NOT_YET_VALID;
        case WC_NO_ERR_TRACE(ASN_AFTER_DATE_E):
            return WOLFSSL_X509_V_ERR_CERT_HAS_EXPIRED;
        case WC_NO_ERR_TRACE(ASN_NO_SIGNER_E):
            /* get issuer error if no CA found locally */
            return WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
        case WC_NO_ERR_TRACE(ASN_SELF_SIGNED_E):
            return WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
        case WC_NO_ERR_TRACE(ASN_PATHLEN_INV_E):
        case WC_NO_ERR_TRACE(ASN_PATHLEN_SIZE_E):
            return WOLFSSL_X509_V_ERR_PATH_LENGTH_EXCEEDED;
        case WC_NO_ERR_TRACE(ASN_SIG_OID_E):
        case WC_NO_ERR_TRACE(ASN_SIG_CONFIRM_E):
        case WC_NO_ERR_TRACE(ASN_SIG_HASH_E):
        case WC_NO_ERR_TRACE(ASN_SIG_KEY_E):
            return WOLFSSL_X509_V_ERR_CERT_SIGNATURE_FAILURE;
        /* We can't disambiguate if its the before or after date that caused
         * the error. Assume expired. */
        case WC_NO_ERR_TRACE(CRL_CERT_DATE_ERR):
            return WOLFSSL_X509_V_ERR_CRL_HAS_EXPIRED;
        case WC_NO_ERR_TRACE(CRL_CERT_REVOKED):
            return WOLFSSL_X509_V_ERR_CERT_REVOKED;
        case WC_NO_ERR_TRACE(CRL_MISSING):
            return WOLFSSL_X509_V_ERR_UNABLE_TO_GET_CRL;
        case 0:
        case 1:
            return 0;
        default:
#ifdef HAVE_WOLFSSL_MSG_EX
            WOLFSSL_MSG_EX("Error not configured or implemented yet: %d", e);
#else
            WOLFSSL_MSG("Error not configured or implemented yet");
#endif
            return e;
    }
}

static void SetupStoreCtxError_ex(WOLFSSL_X509_STORE_CTX* ctx, int ret,
                                                                    int depth)
{
    int error = GetX509Error(ret);

    wolfSSL_X509_STORE_CTX_set_error(ctx, error);
    wolfSSL_X509_STORE_CTX_set_error_depth(ctx, depth);
}

static void SetupStoreCtxError(WOLFSSL_X509_STORE_CTX* ctx, int ret)
{
    int depth = 0;

    /* Set error depth */
    if (ctx->chain)
        depth = (int)ctx->chain->num;

    SetupStoreCtxError_ex(ctx, ret, depth);
}

static int X509StoreVerifyCert(WOLFSSL_X509_STORE_CTX* ctx)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    WOLFSSL_ENTER("X509StoreVerifyCert");

    if (ctx->current_cert != NULL && ctx->current_cert->derCert != NULL) {
        ret = wolfSSL_CertManagerVerifyBuffer(ctx->store->cm,
                    ctx->current_cert->derCert->buffer,
                    ctx->current_cert->derCert->length,
                    WOLFSSL_FILETYPE_ASN1);
        SetupStoreCtxError(ctx, ret);
    #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
        if (ctx->store->verify_cb)
            ret = ctx->store->verify_cb(ret >= 0 ? 1 : 0, ctx) == 1 ?
                                                        WOLFSSL_SUCCESS : ret;
    #endif

    #ifndef NO_ASN_TIME
        if (ret != WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E) &&
            ret != WC_NO_ERR_TRACE(ASN_AFTER_DATE_E)) {
            /* wolfSSL_CertManagerVerifyBuffer only returns ASN_AFTER_DATE_E or
             * ASN_BEFORE_DATE_E if there are no additional errors found in the
             * cert. Therefore, check if the cert is expired or not yet valid
             * in order to return the correct expected error. */
            byte *afterDate = ctx->current_cert->notAfter.data;
            byte *beforeDate = ctx->current_cert->notBefore.data;

            if (XVALIDATE_DATE(afterDate,
                    (byte)ctx->current_cert->notAfter.type, ASN_AFTER) < 1) {
                ret = ASN_AFTER_DATE_E;
            }
            else if (XVALIDATE_DATE(beforeDate,
                    (byte)ctx->current_cert->notBefore.type, ASN_BEFORE) < 1) {
                ret = ASN_BEFORE_DATE_E;
            }
            SetupStoreCtxError(ctx, ret);
        #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
            if (ctx->store->verify_cb)
                ret = ctx->store->verify_cb(ret >= 0 ? 1 : 0,
                                            ctx) == 1 ? WOLFSSL_SUCCESS : -1;
        #endif
        }
    #endif
    }

    return ret;
}

static int addAllButSelfSigned(WOLF_STACK_OF(WOLFSSL_X509)*to,
                               WOLF_STACK_OF(WOLFSSL_X509)*from, int *numAdded)
{
    int ret = WOLFSSL_SUCCESS;
    int i = 0;
    int cnt = 0;
    WOLFSSL_X509 *x = NULL;

    for (i = 0; i < wolfSSL_sk_X509_num(from); i++) {
        x = wolfSSL_sk_X509_value(from, i);
        if (wolfSSL_X509_NAME_cmp(&x->issuer, &x->subject) != 0) {
            if (wolfSSL_sk_X509_push(to, x) <= 0) {
                ret = WOLFSSL_FAILURE;
                goto exit;
            }
            cnt++;
        }
    }

exit:
    if (numAdded != NULL) {
        *numAdded = cnt;
    }
    return ret;
}

/* Verifies certificate chain using WOLFSSL_X509_STORE_CTX
 * returns 0 on success or < 0 on failure.
 */
int wolfSSL_X509_verify_cert(WOLFSSL_X509_STORE_CTX* ctx)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    int done = 0;
    int added = 0;
    int i = 0;
    int numInterAdd = 0;
    int depth = 0;
    WOLFSSL_X509 *issuer = NULL;
    WOLFSSL_X509 *orig = NULL;
    WOLF_STACK_OF(WOLFSSL_X509)* certs = NULL;
    WOLF_STACK_OF(WOLFSSL_X509)* certsToUse = NULL;
    WOLFSSL_ENTER("wolfSSL_X509_verify_cert");

    if (ctx == NULL || ctx->store == NULL || ctx->store->cm == NULL
         || ctx->current_cert == NULL || ctx->current_cert->derCert == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    certs = ctx->store->certs;
    if (ctx->setTrustedSk != NULL) {
        certs = ctx->setTrustedSk;
    }

    if (certs == NULL &&
        wolfSSL_sk_X509_num(ctx->ctxIntermediates) > 0) {
        certsToUse = wolfSSL_sk_X509_new_null();
        ret = addAllButSelfSigned(certsToUse, ctx->ctxIntermediates, NULL);
    }
    else {
        /* Add the intermediates provided on init to the list of untrusted
         * intermediates to be used */
        ret = addAllButSelfSigned(certs, ctx->ctxIntermediates, &numInterAdd);
    }
    if (ret != WOLFSSL_SUCCESS) {
        goto exit;
    }

    if (ctx->chain != NULL) {
        wolfSSL_sk_X509_free(ctx->chain);
    }
    ctx->chain = wolfSSL_sk_X509_new_null();

    if (ctx->depth > 0) {
        depth = ctx->depth + 1;
    }
    else {
        depth = WOLFSSL_X509_STORE_DEFAULT_MAX_DEPTH + 1;
    }

    orig = ctx->current_cert;
    while(done == 0 && depth > 0) {
        issuer = NULL;

        /* Try to find an untrusted issuer first */
        ret = X509StoreGetIssuerEx(&issuer, certs,
                                               ctx->current_cert);
        if (ret == WOLFSSL_SUCCESS) {
            if (ctx->current_cert == issuer) {
                wolfSSL_sk_X509_push(ctx->chain, ctx->current_cert);
                break;
            }

            /* We found our issuer in the non-trusted cert list, add it
             * to the CM and verify the current cert against it */
        #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
            /* OpenSSL doesn't allow the cert as CA if it is not CA:TRUE for
             * intermediate certs.
             */
            if (!issuer->isCa) {
                /* error depth is current depth + 1 */
                SetupStoreCtxError_ex(ctx, X509_V_ERR_INVALID_CA,
                                (ctx->chain) ? (int)(ctx->chain->num + 1) : 1);
                if (ctx->store->verify_cb) {
                    ret = ctx->store->verify_cb(0, ctx);
                    if (ret != WOLFSSL_SUCCESS) {
                        goto exit;
                    }
                }
            } else {
        #endif
            ret = X509StoreAddCa(ctx->store, issuer,
                                            WOLFSSL_TEMP_CA);
            if (ret != WOLFSSL_SUCCESS) {
                goto exit;
            }
            added = 1;
            ret = X509StoreVerifyCert(ctx);
            if (ret != WOLFSSL_SUCCESS) {
                goto exit;
            }
            /* Add it to the current chain and look at the issuer cert next */
            wolfSSL_sk_X509_push(ctx->chain, ctx->current_cert);
        #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
            }
        #endif
            ctx->current_cert = issuer;
        }
        else if (ret == WC_NO_ERR_TRACE(WOLFSSL_FAILURE)) {
            /* Could not find in untrusted list, only place left is
             * a trusted CA in the CM */
            ret = X509StoreVerifyCert(ctx);
            if (ret != WOLFSSL_SUCCESS) {
                if (((ctx->flags & WOLFSSL_PARTIAL_CHAIN) ||
                     (ctx->store->param->flags & WOLFSSL_PARTIAL_CHAIN)) &&
                    (added == 1)) {
                    wolfSSL_sk_X509_push(ctx->chain, ctx->current_cert);
                    ret = WOLFSSL_SUCCESS;
                }
                goto exit;
            }

            /* Cert verified, finish building the chain */
            wolfSSL_sk_X509_push(ctx->chain, ctx->current_cert);
            issuer = NULL;
    #ifdef WOLFSSL_SIGNER_DER_CERT
            x509GetIssuerFromCM(&issuer, ctx->store->cm, ctx->current_cert);
            if (issuer != NULL && ctx->owned != NULL) {
                wolfSSL_sk_X509_push(ctx->owned, issuer);
            }
    #else
            if (ctx->setTrustedSk == NULL) {
                X509StoreGetIssuerEx(&issuer,
                    ctx->store->trusted, ctx->current_cert);
            }
            else {
                X509StoreGetIssuerEx(&issuer,
                    ctx->setTrustedSk, ctx->current_cert);
            }
    #endif
            if (issuer != NULL) {
                wolfSSL_sk_X509_push(ctx->chain, issuer);
            }

            done = 1;
        }
        else {
            goto exit;
        }

        depth--;
    }

exit:
    /* Remove additional intermediates from init from the store */
    if (ctx != NULL && numInterAdd > 0) {
        for (i = 0; i < numInterAdd; i++) {
            wolfSSL_sk_X509_pop(ctx->store->certs);
        }
    }
    /* Remove intermediates that were added to CM */
    if (ctx != NULL) {
        if (ctx->store != NULL) {
            if (added == 1) {
                wolfSSL_CertManagerUnloadTempIntermediateCerts(ctx->store->cm);
            }
        }
        if (orig != NULL) {
            ctx->current_cert = orig;
        }
    }
    if (certsToUse != NULL) {
        wolfSSL_sk_X509_free(certsToUse);
    }

    return ret == WOLFSSL_SUCCESS ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get_current_cert(
                                                WOLFSSL_X509_STORE_CTX* ctx)
    {
        WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_get_current_cert");
        if (ctx)
            return ctx->current_cert;
        return NULL;
    }


    int wolfSSL_X509_STORE_CTX_get_error(WOLFSSL_X509_STORE_CTX* ctx)
    {
        WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_get_error");
        if (ctx != NULL)
            return ctx->error;
        return 0;
    }


    int wolfSSL_X509_STORE_CTX_get_error_depth(WOLFSSL_X509_STORE_CTX* ctx)
    {
        WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_get_error_depth");
        if(ctx)
            return ctx->error_depth;
        return WOLFSSL_FATAL_ERROR;
    }

/* get X509_STORE_CTX ex_data, max idx is MAX_EX_DATA */
void* wolfSSL_X509_STORE_CTX_get_ex_data(WOLFSSL_X509_STORE_CTX* ctx, int idx)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_get_ex_data");
#ifdef HAVE_EX_DATA
    if (ctx != NULL) {
        return wolfSSL_CRYPTO_get_ex_data(&ctx->ex_data, idx);
    }
#else
    (void)ctx;
    (void)idx;
#endif
    return NULL;
}
#endif /* OPENSSL_EXTRA || WOLFSSL_WPAS_SMALL */

#ifdef OPENSSL_EXTRA
    void wolfSSL_X509_STORE_CTX_set_verify_cb(WOLFSSL_X509_STORE_CTX *ctx,
                                  WOLFSSL_X509_STORE_CTX_verify_cb verify_cb)
    {
        WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_set_verify_cb");
        if(ctx == NULL)
            return;
        ctx->verify_cb = verify_cb;
    }

/* Gets pointer to X509_STORE that was used to create context.
 *
 * Return valid pointer on success, NULL if ctx was NULL or not initialized
 */
WOLFSSL_X509_STORE* wolfSSL_X509_STORE_CTX_get0_store(
        WOLFSSL_X509_STORE_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_get0_store");

    if (ctx == NULL)
        return NULL;

    return ctx->store;
}

WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get0_cert(WOLFSSL_X509_STORE_CTX* ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->current_cert;
}

void wolfSSL_X509_STORE_CTX_set_time(WOLFSSL_X509_STORE_CTX* ctx,
                                    unsigned long flags,
                                    time_t t)
{
    (void)flags;

    if (ctx == NULL || ctx->param == NULL)
        return;

    ctx->param->check_time = t;
    ctx->param->flags |= WOLFSSL_USE_CHECK_TIME;
}

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
#ifndef NO_WOLFSSL_STUB
int wolfSSL_X509_STORE_CTX_set_purpose(WOLFSSL_X509_STORE_CTX *ctx,
                                       int purpose)
{
    (void)ctx;
    (void)purpose;
    WOLFSSL_STUB("wolfSSL_X509_STORE_CTX_set_purpose (not implemented)");
    return 0;
}
#endif /* !NO_WOLFSSL_STUB */

#endif /* WOLFSSL_QT || OPENSSL_ALL */
#endif /* OPENSSL_EXTRA */

#ifdef OPENSSL_EXTRA

void wolfSSL_X509_STORE_CTX_set_flags(WOLFSSL_X509_STORE_CTX *ctx,
        unsigned long flags)
{
    if ((ctx != NULL) && (flags & WOLFSSL_PARTIAL_CHAIN)){
        ctx->flags |= WOLFSSL_PARTIAL_CHAIN;
    }
}

/* set X509_STORE_CTX ex_data, max idx is MAX_EX_DATA. Return WOLFSSL_SUCCESS
 * on success, WOLFSSL_FAILURE on error. */
int wolfSSL_X509_STORE_CTX_set_ex_data(WOLFSSL_X509_STORE_CTX* ctx, int idx,
                                       void *data)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_set_ex_data");
#ifdef HAVE_EX_DATA
    if (ctx != NULL)
    {
        return wolfSSL_CRYPTO_set_ex_data(&ctx->ex_data, idx, data);
    }
#else
    (void)ctx;
    (void)idx;
    (void)data;
#endif
    return WOLFSSL_FAILURE;
}

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
/* set X509_STORE_CTX ex_data, max idx is MAX_EX_DATA. Return WOLFSSL_SUCCESS
 * on success, WOLFSSL_FAILURE on error. */
int wolfSSL_X509_STORE_CTX_set_ex_data_with_cleanup(
    WOLFSSL_X509_STORE_CTX* ctx,
    int idx,
    void *data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_set_ex_data_with_cleanup");
    if (ctx != NULL)
    {
        return wolfSSL_CRYPTO_set_ex_data_with_cleanup(&ctx->ex_data, idx,
                                                        data, cleanup_routine);
    }
    return WOLFSSL_FAILURE;
}
#endif /* HAVE_EX_DATA_CLEANUP_HOOKS */

#if defined(WOLFSSL_APACHE_HTTPD) || defined(OPENSSL_ALL)
void wolfSSL_X509_STORE_CTX_set_depth(WOLFSSL_X509_STORE_CTX* ctx, int depth)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_set_depth");
    if (ctx)
        ctx->depth = depth;
}
#endif

WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get0_current_issuer(
        WOLFSSL_X509_STORE_CTX* ctx)
{
    WOLFSSL_STACK* node;
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_get0_current_issuer");

    if (ctx == NULL)
        return NULL;

    /* get0 only checks currently built chain */
    if (ctx->chain != NULL) {
        for (node = ctx->chain; node != NULL; node = node->next) {
            if (wolfSSL_X509_check_issued(node->data.x509,
                                          ctx->current_cert) ==
                                                WOLFSSL_X509_V_OK) {
                return node->data.x509;
            }
        }
    }

    return NULL;
}

/* Set an error stat in the X509 STORE CTX
 *
 */
void wolfSSL_X509_STORE_CTX_set_error(WOLFSSL_X509_STORE_CTX* ctx, int er)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_set_error");

    if (ctx != NULL) {
        ctx->error = er;
    }
}

/* Set the error depth in the X509 STORE CTX */
void wolfSSL_X509_STORE_CTX_set_error_depth(WOLFSSL_X509_STORE_CTX* ctx,
                                                                    int depth)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_set_error_depth");

    if (ctx != NULL) {
        ctx->error_depth = depth;
    }
}

WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get_chain(WOLFSSL_X509_STORE_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_get_chain");

    if (ctx == NULL) {
        return NULL;
    }

#ifdef SESSION_CERTS
    /* if chain is null but sesChain is available then populate stack */
    if (ctx->chain == NULL && ctx->sesChain != NULL) {
        int i;
        int error = 0;
        WOLFSSL_X509_CHAIN* c = ctx->sesChain;
        WOLFSSL_STACK*     sk = wolfSSL_sk_new_node(ctx->heap);

        if (sk == NULL)
            return NULL;

#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_EXTRA)
        /* add CA used to verify top of chain to the list */
        if (c->count > 0) {
            WOLFSSL_X509* x509 = wolfSSL_get_chain_X509(c, c->count - 1);
            WOLFSSL_X509* issuer = NULL;
            if (x509 != NULL) {
                if (wolfSSL_X509_STORE_CTX_get1_issuer(&issuer, ctx, x509)
                        == WOLFSSL_SUCCESS) {
                    /* check that the certificate being looked up is not self
                     * signed and that a issuer was found */
                    if (issuer != NULL && wolfSSL_X509_NAME_cmp(&x509->issuer,
                                &x509->subject) != 0) {
                        if (wolfSSL_sk_X509_push(sk, issuer) <= 0) {
                            WOLFSSL_MSG("Unable to load CA x509 into stack");
                            error = 1;
                        }
                    }
                    else {
                        WOLFSSL_MSG("Certificate is self signed");
                        wolfSSL_X509_free(issuer);
                    }
                }
                else {
                    WOLFSSL_MSG("Could not find CA for certificate");
                }
            }
            wolfSSL_X509_free(x509);
            if (error) {
                wolfSSL_sk_X509_pop_free(sk, NULL);
                wolfSSL_X509_free(issuer);
                return NULL;
            }
        }
#endif

        for (i = c->count - 1; i >= 0; i--) {
            WOLFSSL_X509* x509 = wolfSSL_get_chain_X509(c, i);

            if (x509 == NULL) {
                WOLFSSL_MSG("Unable to get x509 from chain");
                error = 1;
                break;
            }

            if (wolfSSL_sk_X509_push(sk, x509) <= 0) {
                WOLFSSL_MSG("Unable to load x509 into stack");
                wolfSSL_X509_free(x509);
                error = 1;
                break;
            }
        }
        if (error) {
            wolfSSL_sk_X509_pop_free(sk, NULL);
            return NULL;
        }
        ctx->chain = sk;
    }
#endif /* SESSION_CERTS */

    return ctx->chain;
}

/* like X509_STORE_CTX_get_chain(), but return a copy with data reference
   counts increased */
WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get1_chain(WOLFSSL_X509_STORE_CTX* ctx)
{
    WOLFSSL_STACK* ref;

    if (ctx == NULL) {
        return NULL;
    }

    /* get chain in ctx */
    ref = wolfSSL_X509_STORE_CTX_get_chain(ctx);
    if (ref == NULL) {
        return ref;
    }

    /* create duplicate of ctx chain */
    return wolfSSL_sk_dup(ref);
}

#ifndef NO_WOLFSSL_STUB
WOLFSSL_X509_STORE_CTX *wolfSSL_X509_STORE_CTX_get0_parent_ctx(
                                                   WOLFSSL_X509_STORE_CTX *ctx)
{
    (void)ctx;
    WOLFSSL_STUB("wolfSSL_X509_STORE_CTX_get0_parent_ctx");
    return NULL;
}

int wolfSSL_X509_STORE_get_by_subject(WOLFSSL_X509_STORE_CTX* ctx, int idx,
                            WOLFSSL_X509_NAME* name, WOLFSSL_X509_OBJECT* obj)
{
    (void)ctx;
    (void)idx;
    (void)name;
    (void)obj;
    WOLFSSL_STUB("X509_STORE_get_by_subject");
    return 0;
}
#endif

WOLFSSL_X509_VERIFY_PARAM *wolfSSL_X509_STORE_CTX_get0_param(
        WOLFSSL_X509_STORE_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->param;
}

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
#if defined(WOLFSSL_SIGNER_DER_CERT)
WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_X509_STORE_get1_certs(
    WOLFSSL_X509_STORE_CTX* ctx, WOLFSSL_X509_NAME* name)
{
    WOLF_STACK_OF(WOLFSSL_X509)* ret = NULL;
    int err = 0;
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_STACK* sk = NULL;
    WOLFSSL_STACK* certToFilter = NULL;
    WOLFSSL_X509_NAME* certToFilterName = NULL;
    WOLF_STACK_OF(WOLFSSL_X509)* filteredCerts = NULL;
    WOLFSSL_X509* filteredCert = NULL;

    WOLFSSL_ENTER("wolfSSL_X509_STORE_get1_certs");

    if (name == NULL) {
        err = 1;
    }

    if (err == 0) {
        store = wolfSSL_X509_STORE_CTX_get0_store(ctx);
        if (store == NULL) {
            err = 1;
        }
    }

    if (err == 0) {
        filteredCerts = wolfSSL_sk_X509_new_null();
        if (filteredCerts == NULL) {
            err = 1;
        }
    }

    if (err == 0) {
        sk = wolfSSL_CertManagerGetCerts(store->cm);
        if (sk == NULL) {
            err = 1;
        }
    }

    if (err == 0) {
        certToFilter = sk;
        while (certToFilter != NULL) {
            certToFilterName = wolfSSL_X509_get_subject_name(
                                    certToFilter->data.x509);
            if (certToFilterName != NULL) {
                if (wolfSSL_X509_NAME_cmp(certToFilterName, name) == 0) {
                    filteredCert = wolfSSL_X509_dup(certToFilter->data.x509);
                    if (filteredCert == NULL ||
                            wolfSSL_sk_X509_push(filteredCerts, filteredCert)
                                <= 0) {
                        err = 1;
                        wolfSSL_X509_free(filteredCert);
                        break;
                    }
                }
            }
            certToFilter = certToFilter->next;
        }
    }

    if (err == 1) {
        if (filteredCerts != NULL) {
            wolfSSL_sk_X509_pop_free(filteredCerts, NULL);
        }
        ret = NULL;
    }
    else {
        ret = filteredCerts;
    }

    if (sk != NULL) {
        wolfSSL_sk_X509_pop_free(sk, NULL);
    }

    return ret;
}
#endif /* WOLFSSL_SIGNER_DER_CERT */

#endif /* OPENSSL_EXTRA && !NO_FILESYSTEM */

#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
int wolfSSL_X509_STORE_CTX_get1_issuer(WOLFSSL_X509 **issuer,
    WOLFSSL_X509_STORE_CTX *ctx, WOLFSSL_X509 *x)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_get1_issuer");

    if (issuer == NULL || ctx == NULL || x == NULL)
        return WOLFSSL_FATAL_ERROR;

    ret = X509StoreGetIssuerEx(issuer, ctx->store->certs, x);
    if ((ret == WOLFSSL_SUCCESS) && (*issuer != NULL)) {
        return wolfSSL_X509_up_ref(*issuer);
    }

#ifdef WOLFSSL_SIGNER_DER_CERT
    ret = x509GetIssuerFromCM(issuer, ctx->store->cm, x);
#else
    ret = X509StoreGetIssuerEx(issuer, ctx->store->trusted, x);
    if ((ret == WOLFSSL_SUCCESS) && (*issuer != NULL)) {
        return wolfSSL_X509_up_ref(*issuer);
    }
#endif

    return ret;
}
#endif /* WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || OPENSSL_ALL */

#ifdef OPENSSL_EXTRA

static int X509StoreGetIssuerEx(WOLFSSL_X509 **issuer,
                            WOLFSSL_STACK * certs, WOLFSSL_X509 *x)
{
    int i;

    if (issuer == NULL || x == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (certs != NULL) {
        for (i = 0; i < wolfSSL_sk_X509_num(certs); i++) {
            if (wolfSSL_X509_check_issued(
                    wolfSSL_sk_X509_value(certs, i), x) ==
                    WOLFSSL_X509_V_OK) {
                *issuer = wolfSSL_sk_X509_value(certs, i);
                return WOLFSSL_SUCCESS;
            }
        }
    }

    return WOLFSSL_FAILURE;
}

#endif

/******************************************************************************
 * END OF X509_STORE_CTX APIs
 *****************************************************************************/

/******************************************************************************
 * START OF X509_STORE APIs
 *****************************************************************************/

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || \
    defined(WOLFSSL_WPAS_SMALL)
WOLFSSL_X509_STORE* wolfSSL_X509_STORE_new(void)
{
    int ret;
    WOLFSSL_X509_STORE* store = NULL;
    WOLFSSL_ENTER("wolfSSL_X509_STORE_new");

    if ((store = (WOLFSSL_X509_STORE*)XMALLOC(sizeof(WOLFSSL_X509_STORE), NULL,
                                    DYNAMIC_TYPE_X509_STORE)) == NULL)
        goto err_exit;

    XMEMSET(store, 0, sizeof(WOLFSSL_X509_STORE));
    store->isDynamic = 1;

    wolfSSL_RefInit(&store->ref, &ret);
#ifdef WOLFSSL_REFCNT_ERROR_RETURN
    if (ret != 0)
        goto err_exit;
#else
    (void)ret;
#endif

    if ((store->cm = wolfSSL_CertManagerNew()) == NULL)
        goto err_exit;

#ifdef OPENSSL_EXTRA
    if ((store->certs = wolfSSL_sk_X509_new_null()) == NULL)
        goto err_exit;

    if ((store->owned = wolfSSL_sk_X509_new_null()) == NULL)
        goto err_exit;

    if ((store->trusted = wolfSSL_sk_X509_new_null()) == NULL)
        goto err_exit;
#endif

#ifdef HAVE_CRL
    store->crl = store->cm->crl;
#endif

    store->numAdded = 0;

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)

    /* Link store's new Certificate Manager to self by default */
    store->cm->x509_store_p = store;

    if ((store->param = (WOLFSSL_X509_VERIFY_PARAM*)XMALLOC(
                           sizeof(WOLFSSL_X509_VERIFY_PARAM),
                           NULL, DYNAMIC_TYPE_OPENSSL)) == NULL) {
        goto err_exit;
    }
    XMEMSET(store->param, 0, sizeof(WOLFSSL_X509_VERIFY_PARAM));
    if ((store->lookup.dirs = (WOLFSSL_BY_DIR*)XMALLOC(sizeof(WOLFSSL_BY_DIR),
                           NULL, DYNAMIC_TYPE_OPENSSL)) == NULL) {
        WOLFSSL_MSG("store->lookup.dir memory allocation error");
        goto err_exit;
    }
    XMEMSET(store->lookup.dirs, 0, sizeof(WOLFSSL_BY_DIR));
    if (wc_InitMutex(&store->lookup.dirs->lock) != 0) {
            WOLFSSL_MSG("Bad mutex init");
            goto err_exit;
    }
#endif

    return store;

err_exit:
    if (store == NULL)
        return NULL;

    wolfSSL_X509_STORE_free(store);

    return NULL;
}

#ifdef OPENSSL_ALL
static void X509StoreFreeObjList(WOLFSSL_X509_STORE* store,
                  WOLF_STACK_OF(WOLFSSL_X509_OBJECT)* objs)
{
    int i;
    WOLFSSL_X509_OBJECT *obj = NULL;
    int cnt = store->numAdded;

    /* -1 here because it is later used as an index value into the object stack.
     * With there being the chance that the only object in the stack is one from
     * the numAdded to the store >= is used when comparing to 0. */
    i = wolfSSL_sk_X509_OBJECT_num(objs) - 1;
    while (cnt > 0 && i >= 0) {
        /* The inner X509 is owned by somebody else, NULL out the reference */
        obj = (WOLFSSL_X509_OBJECT *)wolfSSL_sk_X509_OBJECT_value(objs, i);
        if (obj != NULL) {
            obj->type = (WOLFSSL_X509_LOOKUP_TYPE)0;
            obj->data.ptr = NULL;
        }
        cnt--;
        i--;
    }

    wolfSSL_sk_X509_OBJECT_pop_free(objs, NULL);
}
#endif

void wolfSSL_X509_STORE_free(WOLFSSL_X509_STORE* store)
{
    int doFree = 0;
    if (store != NULL && store->isDynamic) {
        int ret;
        wolfSSL_RefDec(&store->ref, &doFree, &ret);
    #ifdef WOLFSSL_REFCNT_ERROR_RETURN
        if (ret != 0) {
            WOLFSSL_MSG("Couldn't lock store mutex");
        }
    #else
        (void)ret;
    #endif

        if (doFree) {
#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
            wolfSSL_CRYPTO_cleanup_ex_data(&store->ex_data);
#endif
            if (store->cm != NULL) {
                wolfSSL_CertManagerFree(store->cm);
                store->cm = NULL;
            }
#if defined(OPENSSL_EXTRA)
            if (store->certs != NULL) {
                wolfSSL_sk_X509_pop_free(store->certs, NULL);
                store->certs = NULL;
            }
            if (store->owned != NULL) {
                wolfSSL_sk_X509_pop_free(store->owned, NULL);
                store->owned = NULL;
            }
            if (store->trusted != NULL) {
                wolfSSL_sk_X509_pop_free(store->trusted, NULL);
                store->trusted = NULL;
            }
#endif
#ifdef OPENSSL_ALL
            if (store->objs != NULL) {
                X509StoreFreeObjList(store, store->objs);
            }
#endif
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
            XFREE(store->param, NULL, DYNAMIC_TYPE_OPENSSL);
            store->param = NULL;

            if (store->lookup.dirs != NULL) {
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
                if (store->lookup.dirs->dir_entry) {
                    wolfSSL_sk_BY_DIR_entry_free(
                        store->lookup.dirs->dir_entry);
                }
#endif
                wc_FreeMutex(&store->lookup.dirs->lock);
                XFREE(store->lookup.dirs, NULL, DYNAMIC_TYPE_OPENSSL);
                store->lookup.dirs = NULL;
            }
#endif
            wolfSSL_RefFree(&store->ref);
            XFREE(store, NULL, DYNAMIC_TYPE_X509_STORE);
        }
    }
}

/**
 * Get ex_data in WOLFSSL_STORE at given index
 * @param store a pointer to WOLFSSL_X509_STORE structure
 * @param idx   Index of ex_data to get data from
 * @return void pointer to ex_data on success or NULL on failure
 */
void* wolfSSL_X509_STORE_get_ex_data(WOLFSSL_X509_STORE* store, int idx)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_get_ex_data");
#ifdef HAVE_EX_DATA
    if (store != NULL && idx < MAX_EX_DATA && idx >= 0) {
        return wolfSSL_CRYPTO_get_ex_data(&store->ex_data, idx);
    }
#else
    (void)store;
    (void)idx;
#endif
    return NULL;
}

int wolfSSL_X509_STORE_up_ref(WOLFSSL_X509_STORE* store)
{
    if (store) {
        int ret;
        wolfSSL_RefInc(&store->ref, &ret);
    #ifdef WOLFSSL_REFCNT_ERROR_RETURN
        if (ret != 0) {
            WOLFSSL_MSG("Failed to lock store mutex");
            return WOLFSSL_FAILURE;
        }
    #else
        (void)ret;
    #endif

        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}

/**
 * Set ex_data for WOLFSSL_STORE
 * @param store a pointer to WOLFSSL_X509_STORE structure
 * @param idx   Index of ex data to set
 * @param data  Data to set in ex data
 * @return WOLFSSL_SUCCESS on success or WOLFSSL_FAILURE on failure
 */
int wolfSSL_X509_STORE_set_ex_data(WOLFSSL_X509_STORE* store, int idx,
                                                                void *data)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_set_ex_data");
#ifdef HAVE_EX_DATA
    if (store != NULL && idx < MAX_EX_DATA) {
        return wolfSSL_CRYPTO_set_ex_data(&store->ex_data, idx, data);
    }
#else
    (void)store;
    (void)idx;
    (void)data;
#endif
    return WOLFSSL_FAILURE;
}

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
/**
 * Set ex_data for WOLFSSL_STORE
 * @param store a pointer to WOLFSSL_X509_STORE structure
 * @param idx   Index of ex data to set
 * @param data  Data to set in ex data
 * @return WOLFSSL_SUCCESS on success or WOLFSSL_FAILURE on failure
 */
int wolfSSL_X509_STORE_set_ex_data_with_cleanup(
    WOLFSSL_X509_STORE* store,
    int idx,
    void *data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_set_ex_data_with_cleanup");
    if (store != NULL && idx < MAX_EX_DATA) {
        return wolfSSL_CRYPTO_set_ex_data_with_cleanup(&store->ex_data, idx,
                                                       data, cleanup_routine);
    }
    return WOLFSSL_FAILURE;
}

#endif /* HAVE_EX_DATA_CLEANUP_HOOKS */

#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER || WOLFSSL_WPAS_SMALL */

#ifdef OPENSSL_EXTRA

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
void wolfSSL_X509_STORE_set_verify_cb(WOLFSSL_X509_STORE *st,
        WOLFSSL_X509_STORE_CTX_verify_cb verify_cb)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_set_verify_cb");
    if (st != NULL) {
        st->verify_cb = verify_cb;
    }
}

void wolfSSL_X509_STORE_set_get_crl(WOLFSSL_X509_STORE *st,
        WOLFSSL_X509_STORE_CTX_get_crl_cb get_cb)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_set_get_crl");
    if (st != NULL) {
        st->get_crl_cb = get_cb;
    }
}

#ifndef NO_WOLFSSL_STUB
void wolfSSL_X509_STORE_set_check_crl(WOLFSSL_X509_STORE *st,
        WOLFSSL_X509_STORE_CTX_check_crl_cb check_crl)
{
    (void)st;
    (void)check_crl;
    WOLFSSL_STUB("wolfSSL_X509_STORE_set_check_crl (not implemented)");
}
#endif
#endif /* WOLFSSL_QT || OPENSSL_ALL */

WOLFSSL_X509_LOOKUP* wolfSSL_X509_STORE_add_lookup(WOLFSSL_X509_STORE* store,
                                               WOLFSSL_X509_LOOKUP_METHOD* m)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_add_lookup");
    if (store == NULL || m == NULL)
        return NULL;

    /* Make sure the lookup has a back reference to the store. */
    store->lookup.store = store;
    /* store a type to know which method wants to be used for */
    store->lookup.type = m->type;
    return &store->lookup;
}

static int X509StoreAddCa(WOLFSSL_X509_STORE* store,
                                          WOLFSSL_X509* x509, int type)
{
    int result = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
    DerBuffer* derCert = NULL;

    WOLFSSL_ENTER("X509StoreAddCa");
    if (store != NULL && x509 != NULL && x509->derCert != NULL) {
        result = AllocDer(&derCert, x509->derCert->length,
            x509->derCert->type, NULL);
        if (result == 0) {
            /* AddCA() frees the buffer. */
            XMEMCPY(derCert->buffer,
                            x509->derCert->buffer, x509->derCert->length);
            result = AddCA(store->cm, &derCert, type, VERIFY);
        }
    }

    return result;
}


int wolfSSL_X509_STORE_add_cert(WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509)
{
    int result = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);

    WOLFSSL_ENTER("wolfSSL_X509_STORE_add_cert");
    if (store != NULL && store->cm != NULL && x509 != NULL
                                                && x509->derCert != NULL) {
        /* Mimic the openssl behavior, must be self signed to be considered
         * trusted, addCA() internals will do additional checks for
         * CA=TRUE */
        if (wolfSSL_X509_NAME_cmp(&x509->issuer, &x509->subject) == 0) {
            result = X509StoreAddCa(store, x509, WOLFSSL_USER_CA);
            if (result == WOLFSSL_SUCCESS && store->trusted != NULL) {
                result = wolfSSL_X509_up_ref(x509);
                if (result == WOLFSSL_SUCCESS) {
                    result = wolfSSL_sk_X509_push(store->trusted, x509);
                    if (result > 0) {
                        result = WOLFSSL_SUCCESS;
                    }
                    else {
                        result = WOLFSSL_FATAL_ERROR;
                        wolfSSL_X509_free(x509);
                    }
                }
            }
        }
        else {
            if (store->certs != NULL) {
                result = wolfSSL_X509_up_ref(x509);
                if (result == WOLFSSL_SUCCESS) {
                    result = wolfSSL_sk_X509_push(store->certs, x509);
                    if (result > 0) {
                        result = WOLFSSL_SUCCESS;
                    }
                    else {
                        result = WOLFSSL_FATAL_ERROR;
                        wolfSSL_X509_free(x509);
                    }
                }
            }
            else {
                /* If store->certs is NULL, this is an X509_STORE managed by an
                 * SSL_CTX, preserve behavior and always add as USER_CA */
                result = X509StoreAddCa(
                            store, x509, WOLFSSL_USER_CA);
            }
        }
    }

    WOLFSSL_LEAVE("wolfSSL_X509_STORE_add_cert", result);

    if (result != WOLFSSL_SUCCESS) {
        result = WOLFSSL_FATAL_ERROR;
    }

    return result;
}

int wolfSSL_X509_STORE_set_flags(WOLFSSL_X509_STORE* store, unsigned long flag)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_X509_STORE_set_flags");

    if (store == NULL)
        return WOLFSSL_FAILURE;

    if ((flag & WOLFSSL_CRL_CHECKALL) || (flag & WOLFSSL_CRL_CHECK)) {
        ret = wolfSSL_CertManagerEnableCRL(store->cm, (int)flag);
    }
#if defined(OPENSSL_COMPATIBLE_DEFAULTS)
    else if (flag == 0) {
        ret = wolfSSL_CertManagerDisableCRL(store->cm);
    }
#endif
    if (flag & WOLFSSL_PARTIAL_CHAIN) {
        store->param->flags |= WOLFSSL_PARTIAL_CHAIN;
    }
    return ret;
}


int wolfSSL_X509_STORE_set_default_paths(WOLFSSL_X509_STORE* store)
{
    (void)store;
    return WOLFSSL_SUCCESS;
}

int X509StoreLoadCertBuffer(WOLFSSL_X509_STORE *str,
                                        byte *buf, word32 bufLen, int type)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_X509 *x509 = NULL;

    if (str == NULL || buf == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* OpenSSL X509_STORE_load_file fails on DER file, we will as well */
    x509 = wolfSSL_X509_load_certificate_buffer(buf, bufLen, type);
    if (str->owned != NULL) {
        if (wolfSSL_sk_X509_push(str->owned, x509) <= 0) {
            ret = WOLFSSL_FAILURE;
        }
    }
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_STORE_add_cert(str, x509);
    }
    if (ret != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Failed to load file");
        ret = WOLFSSL_FAILURE;
    }
    if (ret != WOLFSSL_SUCCESS || str->owned == NULL) {
        wolfSSL_X509_free(x509);
    }

    return ret;
}

#if !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)

static int X509StoreReadFile(const char *fname,
                StaticBuffer *content, word32 *bytesRead, int *type)
{
    int ret = -1;
    long sz = 0;
#ifdef HAVE_CRL
    const char* header = NULL;
    const char* footer = NULL;
#endif

    ret = wolfssl_read_file_static(fname, content, NULL, DYNAMIC_TYPE_FILE,
        &sz);
    if (ret == 0) {
        *type = CERT_TYPE;
        *bytesRead = (word32)sz;
#ifdef HAVE_CRL
        /* Look for CRL header and footer. */
        if (wc_PemGetHeaderFooter(CRL_TYPE, &header, &footer) == 0 &&
                (XSTRNSTR((char*)content->buffer, header, (word32)sz) !=
                    NULL)) {
            *type = CRL_TYPE;
        }
#endif
    }

    return (ret == 0 ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE);
}

static int X509StoreLoadFile(WOLFSSL_X509_STORE *str,
                                        const char *fname)
{
    int ret = WOLFSSL_SUCCESS;
    int type = 0;
#ifndef WOLFSSL_SMALL_STACK
    byte   stackBuffer[FILE_BUFFER_SIZE];
#endif
    StaticBuffer content;
    word32 contentLen = 0;

#ifdef WOLFSSL_SMALL_STACK
    static_buffer_init(&content);
#else
    static_buffer_init(&content, stackBuffer, FILE_BUFFER_SIZE);
#endif

    ret = X509StoreReadFile(fname, &content, &contentLen, &type);
    if (ret != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Failed to load file");
        ret = WOLFSSL_FAILURE;
    }

    if ((ret == WOLFSSL_SUCCESS) && (type == CERT_TYPE)) {
        ret = X509StoreLoadCertBuffer(str, content.buffer,
                                        contentLen, WOLFSSL_FILETYPE_PEM);
    }
#ifdef HAVE_CRL
    else if ((ret == WOLFSSL_SUCCESS) && (type == CRL_TYPE)) {
        ret = BufferLoadCRL(str->cm->crl, content.buffer, contentLen,
                                        WOLFSSL_FILETYPE_PEM, 0);
    }
#endif

    static_buffer_free(&content, NULL, DYNAMIC_TYPE_FILE);
    return ret;
}

/* Loads certificate(s) files in pem format into X509_STORE struct from either
 * a file or directory.
 * Returns WOLFSSL_SUCCESS on success or WOLFSSL_FAILURE if an error occurs.
 */
WOLFSSL_API int wolfSSL_X509_STORE_load_locations(WOLFSSL_X509_STORE *str,
                                            const char *file, const char *dir)
{
    WOLFSSL_CTX* ctx;
    char *name = NULL;
    int ret = WOLFSSL_SUCCESS;
#ifdef WOLFSSL_SMALL_STACK
    ReadDirCtx* readCtx = NULL;
#else
    ReadDirCtx  readCtx[1];
#endif

    WOLFSSL_ENTER("wolfSSL_X509_STORE_load_locations");

    if (str == NULL || str->cm == NULL || (file == NULL  && dir == NULL))
        return WOLFSSL_FAILURE;

    /* tmp ctx for setting our cert manager */
    ctx = wolfSSL_CTX_new_ex(cm_pick_method(str->cm->heap), str->cm->heap);
    if (ctx == NULL)
        return WOLFSSL_FAILURE;

    wolfSSL_CertManagerFree(ctx->cm);
    ctx->cm = str->cm;

#ifdef HAVE_CRL
    if (str->cm->crl == NULL) {
        /* Workaround to allocate the internals to load CRL's but don't enable
         * CRL checking by default */
        if (wolfSSL_CertManagerEnableCRL(str->cm, WOLFSSL_CRL_CHECK)
                != WOLFSSL_SUCCESS ||
                wolfSSL_CertManagerDisableCRL(str->cm) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Enable CRL failed");
            wolfSSL_CTX_free(ctx);
            return WOLFSSL_FAILURE;
        }
    }
#endif

    /* Load individual file */
    if (file) {
        ret = X509StoreLoadFile(str, file);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Failed to load file");
            ret = WOLFSSL_FAILURE;
        }
    }

    /* Load files in dir */
    if (dir && ret == WOLFSSL_SUCCESS) {
        int successes = 0;

        #ifdef WOLFSSL_SMALL_STACK
            readCtx = (ReadDirCtx*)XMALLOC(sizeof(ReadDirCtx), ctx->heap,
                                                    DYNAMIC_TYPE_TMP_BUFFER);
            if (readCtx == NULL) {
                WOLFSSL_MSG("Memory error");
                wolfSSL_CTX_free(ctx);
                return WOLFSSL_FAILURE;
            }
        #endif

        /* try to load each regular file in dir */
        ret = wc_ReadDirFirst(readCtx, dir, &name);
        while (ret == 0 && name) {
            WOLFSSL_MSG(name);

            ret = X509StoreLoadFile(str, name);
            /* Not failing on load errors */
            if (ret != WOLFSSL_SUCCESS)
                WOLFSSL_MSG("Failed to load file in path, continuing");
            else
                successes++;

            ret = wc_ReadDirNext(readCtx, dir, &name);
        }
        wc_ReadDirClose(readCtx);

        /* Success if at least one file in dir was loaded */
        if (successes > 0)
            ret = WOLFSSL_SUCCESS;
        else {
            WOLFSSL_ERROR(ret);
            ret = WOLFSSL_FAILURE;
        }

        #ifdef WOLFSSL_SMALL_STACK
            XFREE(readCtx, ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
    }

    ctx->cm = NULL;
    wolfSSL_CTX_free(ctx);

    return ret;
}
#endif /* !NO_FILESYSTEM && !NO_WOLFSSL_DIR */

int wolfSSL_X509_CA_num(WOLFSSL_X509_STORE* store)
{
    int cnt_ret = 0;
    Signer **table;

    WOLFSSL_ENTER("wolfSSL_X509_CA_num");
    if (store == NULL || store->cm == NULL){
        WOLFSSL_MSG("invalid parameter");
        return WOLFSSL_FAILURE;
    }

    table = store->cm->caTable;
    if (table || (store->certs != NULL)){
        if (wc_LockMutex(&store->cm->caLock) == 0){
            if (table) {
                int i = 0;
                for (i = 0; i < CA_TABLE_SIZE; i++) {
                    Signer* signer = table[i];
                    while (signer) {
                        Signer* next = signer->next;
                        cnt_ret++;
                        signer = next;
                    }
                }
            }

            if (store->certs != NULL) {
                cnt_ret += wolfSSL_sk_X509_num(store->certs);
            }
            wc_UnLockMutex(&store->cm->caLock);
        }
    }

    return cnt_ret;
}

/******************************************************************************
* wolfSSL_X509_STORE_GetCerts - retrieve stack of X509 in a certificate
*                               store ctx
*
* This API can be used in SSL verify callback function to view cert chain
* See examples/client/client.c and myVerify() function in test.h
*
* RETURNS:
* returns stack of X509 certs on success, otherwise returns a NULL.
*/
WOLFSSL_STACK* wolfSSL_X509_STORE_GetCerts(WOLFSSL_X509_STORE_CTX* s)
{
    int  certIdx = 0;
    WOLFSSL_BUFFER_INFO* cert = NULL;
    DecodedCert* dCert = NULL;
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_STACK* sk = NULL;
    int found = 0;

    if (s == NULL) {
        return NULL;
    }

    sk = wolfSSL_sk_X509_new_null();

    if (sk == NULL) {
        return NULL;
    }

    for (certIdx = s->totalCerts - 1; certIdx >= 0; certIdx--) {
        /* get certificate buffer */
        cert = &s->certs[certIdx];

        dCert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL,
                                                DYNAMIC_TYPE_DCERT);

        if (dCert == NULL) {
            goto error;
        }
        XMEMSET(dCert, 0, sizeof(DecodedCert));

        InitDecodedCert(dCert, cert->buffer, cert->length, NULL);

        /* Parse Certificate */
        if (ParseCert(dCert, CERT_TYPE, NO_VERIFY, NULL)){
            goto error;
        }
        x509 = wolfSSL_X509_new();

        if (x509 == NULL) {
            goto error;
        }
        InitX509(x509, 1, NULL);

        if (CopyDecodedToX509(x509, dCert) == 0) {

            if (wolfSSL_sk_X509_push(sk, x509) <= 0) {
                WOLFSSL_MSG("Unable to load x509 into stack");
                wolfSSL_X509_free(x509);
                goto error;
            }
        }
        else {
            goto error;
        }
        found = 1;

        FreeDecodedCert(dCert);
        XFREE(dCert, NULL, DYNAMIC_TYPE_DCERT);
        dCert = NULL;
    }

    if (!found) {
        wolfSSL_sk_X509_pop_free(sk, NULL);
        sk = NULL;
    }
    return sk;

error:
    if (dCert) {
        FreeDecodedCert(dCert);
        XFREE(dCert, NULL, DYNAMIC_TYPE_DCERT);
    }

    if (sk)
        wolfSSL_sk_X509_pop_free(sk, NULL);

    return NULL;
}
#endif /* OPENSSL_EXTRA */

#ifdef OPENSSL_ALL
WOLF_STACK_OF(WOLFSSL_X509_OBJECT)* wolfSSL_X509_STORE_get0_objects(
    WOLFSSL_X509_STORE* store)
{
    WOLFSSL_STACK* ret = NULL;
    WOLFSSL_STACK* cert_stack = NULL;
#if ((defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM)) || \
     (defined(HAVE_CRL)))
    WOLFSSL_X509_OBJECT* obj = NULL;
#endif
#if defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM)
    WOLFSSL_X509* x509 = NULL;
    int i = 0;
#endif
    WOLFSSL_ENTER("wolfSSL_X509_STORE_get0_objects");

    if (store == NULL || store->cm == NULL) {
        WOLFSSL_MSG("Missing or empty store");
        return NULL;
    }

    if (store->objs != NULL) {
#if defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM)
        /* want to update objs stack by cm stack again before returning it*/
        X509StoreFreeObjList(store, store->objs);
        store->objs = NULL;
#else
        if (wolfSSL_sk_X509_OBJECT_num(store->objs) == 0) {
            /* Let's try generating the stack again */
            wolfSSL_sk_X509_OBJECT_pop_free(store->objs, NULL);
            store->objs = NULL;
        }
        else
            return store->objs;
#endif
    }

    if ((ret = wolfSSL_sk_X509_OBJECT_new()) == NULL) {
        WOLFSSL_MSG("wolfSSL_sk_X509_OBJECT_new error");
        goto err_cleanup;
    }

#if defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM)
    cert_stack = wolfSSL_CertManagerGetCerts(store->cm);
    store->numAdded = 0;
    if (cert_stack == NULL && wolfSSL_sk_X509_num(store->certs) > 0) {
        cert_stack = wolfSSL_sk_X509_new_null();
        if (cert_stack == NULL) {
            WOLFSSL_MSG("wolfSSL_sk_X509_OBJECT_new error");
            goto err_cleanup;
        }
    }
    for (i = 0; i < wolfSSL_sk_X509_num(store->certs); i++) {
        if (wolfSSL_sk_X509_push(cert_stack,
                             wolfSSL_sk_X509_value(store->certs, i)) > 0) {
            store->numAdded++;
        }
    }
    /* Do not modify stack until after we guarantee success to
     * simplify cleanup logic handling cert merging above */
    for (i = 0; i < wolfSSL_sk_X509_num(cert_stack); i++) {
        x509 = (WOLFSSL_X509 *)wolfSSL_sk_value(cert_stack, i);
        obj  = wolfSSL_X509_OBJECT_new();
        if (obj == NULL) {
            WOLFSSL_MSG("wolfSSL_X509_OBJECT_new error");
            goto err_cleanup;
        }
        if (wolfSSL_sk_X509_OBJECT_push(ret, obj) <= 0) {
            WOLFSSL_MSG("wolfSSL_sk_X509_OBJECT_push error");
            wolfSSL_X509_OBJECT_free(obj);
            goto err_cleanup;
        }
        obj->type = WOLFSSL_X509_LU_X509;
        obj->data.x509 = x509;
    }

    while (wolfSSL_sk_X509_num(cert_stack) > 0) {
        wolfSSL_sk_X509_pop(cert_stack);
    }
#endif

#ifdef HAVE_CRL
    if (store->cm->crl != NULL) {
        obj = wolfSSL_X509_OBJECT_new();
        if (obj == NULL) {
            WOLFSSL_MSG("wolfSSL_X509_OBJECT_new error");
            goto err_cleanup;
        }
        if (wolfSSL_sk_X509_OBJECT_push(ret, obj) <= 0) {
            WOLFSSL_MSG("wolfSSL_sk_X509_OBJECT_push error");
            wolfSSL_X509_OBJECT_free(obj);
            goto err_cleanup;
        }
        obj->type = WOLFSSL_X509_LU_CRL;
        obj->data.crl = store->cm->crl;
    }
#endif

    if (cert_stack)
        wolfSSL_sk_X509_pop_free(cert_stack, NULL);
    store->objs = ret;
    return ret;
err_cleanup:
    if (ret != NULL)
        X509StoreFreeObjList(store, ret);
    if (cert_stack != NULL) {
        while (store->numAdded > 0) {
            wolfSSL_sk_X509_pop(cert_stack);
            store->numAdded--;
        }
        wolfSSL_sk_X509_pop_free(cert_stack, NULL);
    }
    return NULL;
}
#endif /* OPENSSL_ALL */

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || \
    defined(WOLFSSL_WPAS_SMALL)
WOLFSSL_X509_VERIFY_PARAM *wolfSSL_X509_STORE_get0_param(
        const WOLFSSL_X509_STORE *ctx)
{
    if (ctx == NULL)
        return NULL;
    return ctx->param;
}

#ifdef OPENSSL_EXTRA
int wolfSSL_X509_STORE_set1_param(WOLFSSL_X509_STORE *ctx,
        WOLFSSL_X509_VERIFY_PARAM *param)
{
    if (ctx == NULL)
        return WOLFSSL_FAILURE;
    return wolfSSL_X509_VERIFY_PARAM_set1(ctx->param, param);
}
#endif
#endif

/******************************************************************************
 * END OF X509_STORE APIs
 *****************************************************************************/

#endif /* NO_CERTS */

#endif /* !WOLFCRYPT_ONLY */

#endif /* !WOLFSSL_X509_STORE_INCLUDED */

