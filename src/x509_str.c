/* x509_str.c
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
static int X509StoreCertInStack(WOLF_STACK_OF(WOLFSSL_X509)* stack,
                                WOLFSSL_X509* cert);
static int X509StoreCertPartialChainEnabled(WOLFSSL_X509_STORE_CTX* ctx);
static int X509StoreKeySigned(WOLFSSL_X509* ca, WOLFSSL_X509* x, int* err);
static int X509StoreIssued(WOLFSSL_X509* ca, WOLFSSL_X509* x);
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
        if (wolfSSL_X509_STORE_CTX_init(ctx, NULL, NULL, NULL) !=
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
        wolfSSL_X509_VERIFY_PARAM_free(ctx->param);
        ctx->param = NULL;

        if (ctx->chain != NULL) {
            wolfSSL_sk_X509_pop_free(ctx->chain, NULL);
        }

        if (ctx->current_issuer != NULL) {
            wolfSSL_X509_free(ctx->current_issuer);
            ctx->current_issuer = NULL;
        }
#endif

        XFREE(ctx, ctx->heap, DYNAMIC_TYPE_X509_CTX);
    }
}

#ifdef OPENSSL_EXTRA

#if defined(SESSION_CERTS) || defined(WOLFSSL_SIGNER_DER_CERT)

/**
 * Find the issuing cert of the input cert. On a self-issued cert (issuer name
 * equals subject name) this function will return an error.
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
    WC_DECLARE_VAR(cert, DecodedCert, 1, 0);

    if (cm == NULL || x == NULL || x->derCert == NULL) {
        WOLFSSL_MSG("No cert DER buffer or NULL cm. Defining "
                    "WOLFSSL_SIGNER_DER_CERT could solve the issue");
        return WOLFSSL_FAILURE;
    }

    WC_ALLOC_VAR_EX(cert, DecodedCert, 1, NULL, DYNAMIC_TYPE_DCERT,
        return WOLFSSL_FAILURE);

    /* Use existing CA retrieval APIs that use DecodedCert. */
    InitDecodedCert(cert, x->derCert->buffer, x->derCert->length, cm->heap);
    if (ParseCertRelative(cert, CERT_TYPE, 0, NULL, NULL) == 0
            && !cert->selfIssued) {
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
    WC_FREE_VAR_EX(cert, NULL, DYNAMIC_TYPE_DCERT);

    if (ca == NULL)
        return WOLFSSL_FAILURE;

#ifdef WOLFSSL_SIGNER_DER_CERT
    /* populate issuer with Signer DER. A signer restored from a cert cache
     * (cm_restore_cert_row()) carries no DER, so fall back to the empty
     * certificate below rather than dereferencing NULL. */
    if ((ca->derCert != NULL) && (ca->derCert->buffer != NULL)) {
        if (wolfSSL_X509_d2i_ex(issuer, ca->derCert->buffer,
                ca->derCert->length, cm->heap) == NULL)
            return WOLFSSL_FAILURE;
    }
    else
#endif
    {
        /* Create an empty certificate as CA doesn't have a certificate. */
        *issuer = (WOLFSSL_X509 *)XMALLOC(sizeof(WOLFSSL_X509), 0,
            DYNAMIC_TYPE_OPENSSL);
        if (*issuer == NULL)
            return WOLFSSL_FAILURE;

        InitX509((*issuer), 1, NULL);
    }

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
        ctx->setTrustedSk = NULL;
#ifdef HAVE_CRL
        ctx->crls = NULL;
#endif
        if (ctx->chain != NULL) {
            wolfSSL_sk_X509_pop_free(ctx->chain, NULL);
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
        ctx->verify_cb = NULL;
        ctx->error = 0;
        ctx->error_depth = 0;
        ctx->discardSessionCerts = 0;

        /* As X509_VERIFY_PARAM_new(), so set0_param() can replace it */
        if (ctx->param == NULL) {
            ctx->param = (WOLFSSL_X509_VERIFY_PARAM*)XMALLOC(
                           sizeof(WOLFSSL_X509_VERIFY_PARAM),
                           NULL, DYNAMIC_TYPE_OPENSSL);
            if (ctx->param == NULL){
                WOLFSSL_MSG("wolfSSL_X509_STORE_CTX_init failed");
                return WOLFSSL_FAILURE;
            }
        }
        XMEMSET(ctx->param, 0, sizeof(*ctx->param));
        ctx->param->depth = -1;

        /* Inherit the store's parameters, including the hostname / IP the
         * caller expects the peer to present. */
        if (store != NULL && store->param != NULL) {
            if (wolfSSL_X509_VERIFY_PARAM_set1(ctx->param, store->param)
                    != WOLFSSL_SUCCESS) {
                WOLFSSL_MSG("wolfSSL_X509_STORE_CTX_init failed");
                return WOLFSSL_FAILURE;
            }
        }
        /* No depth from the store: use the default, as OpenSSL does */
        if (ctx->param->depth == -1) {
            ctx->param->depth = WOLFSSL_X509_STORE_DEFAULT_MAX_DEPTH;
        }
        /* As OpenSSL's default param */
        ctx->param->flags |= WOLFSSL_TRUSTED_FIRST;

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

        wolfSSL_X509_VERIFY_PARAM_free(ctx->param);
        ctx->param = NULL;

        wolfSSL_X509_STORE_CTX_init(ctx, NULL, NULL, NULL);
    }
}


#ifdef HAVE_CRL
/* Set the CRLs to use during certificate verification. The stack is not
 * copied. The caller keeps ownership and has to keep the stack valid as long
 * as it is set on the ctx. */
void wolfSSL_X509_STORE_CTX_set0_crls(WOLFSSL_X509_STORE_CTX *ctx,
                                      WOLF_STACK_OF(WOLFSSL_X509_CRL) *sk)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_set0_crls");
    if (ctx != NULL) {
        ctx->crls = sk;
    }
}
#endif

void wolfSSL_X509_STORE_CTX_trusted_stack(WOLFSSL_X509_STORE_CTX *ctx,
                                          WOLF_STACK_OF(WOLFSSL_X509) *sk)
{
    if (ctx != NULL) {
        ctx->setTrustedSk = sk;
    }
}


#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
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
        case WC_NO_ERR_TRACE(RPK_UNTRUSTED_E):
            /* RFC 7250 Raw Public Key not trusted out of band. Distinct from
             * the X.509 issuer-lookup error above so verify callbacks that
             * accept ASN_NO_SIGNER_E / UNABLE_TO_GET_ISSUER_CERT_LOCALLY do not
             * accidentally accept an unauthenticated RPK. */
            return WOLFSSL_X509_V_ERR_RPK_UNTRUSTED;
        case WC_NO_ERR_TRACE(DOMAIN_NAME_MISMATCH):
            return WOLFSSL_X509_V_ERR_HOSTNAME_MISMATCH;
        case WC_NO_ERR_TRACE(IPADDR_MISMATCH):
            return WOLFSSL_X509_V_ERR_IP_ADDRESS_MISMATCH;
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
        case WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E):
            return WOLFSSL_X509_V_ERR_UNABLE_TO_GET_CRL;
        case WC_NO_ERR_TRACE(ASN_CRL_CONFIRM_E):
            return WOLFSSL_X509_V_ERR_CRL_SIGNATURE_FAILURE;
        case WC_NO_ERR_TRACE(EXTKEYUSE_AUTH_E):
            return WOLFSSL_X509_V_ERR_INVALID_PURPOSE;
        /* <e> is an internal wolfSSL return code, not an X509_V_* code, so 1
         * here is WOLFSSL_SUCCESS - it does not collide with
         * WOLFSSL_X509_V_ERR_UNSPECIFIED, which shares the value but never
         * reaches this function. */
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
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA

static void SetupStoreCtxError_ex(WOLFSSL_X509_STORE_CTX* ctx, int ret,
                                                                    int depth)
{
    int error = GetX509Error(ret);

    /* Do not overwrite a previously recorded error with success; preserve
     * the worst-seen error across the chain walk. */
    if (error == 0 && ctx->error != 0)
        return;

    wolfSSL_X509_STORE_CTX_set_error(ctx, error);
    wolfSSL_X509_STORE_CTX_set_error_depth(ctx, depth);
}

#ifndef NO_ASN_TIME
/* The verification time, as OpenSSL's: the param time with
 * X509_V_FLAG_USE_CHECK_TIME, none with X509_V_FLAG_NO_CHECK_TIME, else the
 * current time, 0. As in wolfCrypt's date checks, a param time of 0 is the
 * current time. A custom XVALIDATE_DATE always checks against its own time.
 * Returns 0 when dates are not checked, else 1 and the time in *t. */
static int X509StoreCheckTime(WOLFSSL_X509_STORE_CTX* ctx, time_t* t)
{
#ifdef USE_WOLF_VALIDDATE
    WOLFSSL_X509_VERIFY_PARAM* param = ctx->param;

    if (param == NULL && ctx->store != NULL) {
        param = ctx->store->param;
    }
    if (param != NULL && (param->flags & WOLFSSL_USE_CHECK_TIME) != 0) {
        *t = param->check_time;
        return 1;
    }
    if (param != NULL && (param->flags & WOLFSSL_NO_CHECK_TIME) != 0) {
        return 0;
    }
#else
    (void)ctx;
#endif
    *t = 0;
    return 1;
}

/* Checks the validity period of x509 at the verification time.
 * Returns WOLFSSL_SUCCESS, ASN_BEFORE_DATE_E or ASN_AFTER_DATE_E. */
static int X509StoreCheckCertDate(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509* x509)
{
    time_t t;

    if (!X509StoreCheckTime(ctx, &t)) {
        return WOLFSSL_SUCCESS;
    }
#ifdef USE_WOLF_VALIDDATE
    if (t != 0) {
        if (wc_ValidateDateWithTime(x509->notBefore.data,
                (byte)x509->notBefore.type, ASN_BEFORE, t,
                x509->notBefore.length) < 1) {
            return ASN_BEFORE_DATE_E;
        }
        /* Expired at its notAfter, as OpenSSL's X509_cmp_time() */
        if (wc_ValidateDateWithTime(x509->notAfter.data,
                (byte)x509->notAfter.type, ASN_AFTER, t + 1,
                x509->notAfter.length) < 1) {
            return ASN_AFTER_DATE_E;
        }
        return WOLFSSL_SUCCESS;
    }
#endif
    if (XVALIDATE_DATE(x509->notBefore.data, (byte)x509->notBefore.type,
            ASN_BEFORE, x509->notBefore.length) < 1) {
        return ASN_BEFORE_DATE_E;
    }
    if (XVALIDATE_DATE(x509->notAfter.data, (byte)x509->notAfter.type,
            ASN_AFTER, x509->notAfter.length) < 1) {
        return ASN_AFTER_DATE_E;
    }
    return WOLFSSL_SUCCESS;
}

#endif /* NO_ASN_TIME */

#ifdef HAVE_CRL
/* Check ctx->current_cert against the store's CRLs, signed by issuer and
 * current at *checkTime, as CheckCertCRLFromCm() checks them.
 * Returns WOLFSSL_SUCCESS or the CRL error. */
static int X509StoreCheckStoreCrl(WOLFSSL_X509_STORE_CTX* ctx, Signer* issuer,
        const time_t* checkTime)
{
    int ret;
    WC_DECLARE_VAR(cert, DecodedCert, 1, 0);

    WC_ALLOC_VAR_EX(cert, DecodedCert, 1, ctx->heap, DYNAMIC_TYPE_DCERT,
        return MEMORY_E);

    InitDecodedCert(cert, ctx->current_cert->derCert->buffer,
        ctx->current_cert->derCert->length, ctx->heap);
    ret = ParseCertRelative(cert, CERT_TYPE, NO_VERIFY, ctx->store->cm, NULL);
    if (ret == 0) {
        ret = CheckCertCRLFromCm(ctx->store->cm, ctx->store->cm->crl, cert,
            issuer, checkTime);
    }
    FreeDecodedCert(cert);
    WC_FREE_VAR_EX(cert, ctx->heap, DYNAMIC_TYPE_DCERT);

    return (ret == 0) ? WOLFSSL_SUCCESS : ret;
}

/* As OpenSSL's get_crl_sk(), checks the cert with only the best CRL set with
 * X509_STORE_CTX_set0_crls. Returns WOLFSSL_SUCCESS or the CRL error. */
static int X509StoreCheckCtxCrls(WOLFSSL_X509_STORE_CTX* ctx, Signer* issuer,
        const time_t* checkTime)
{
    int ret;
    int i;
    int numCrls;
    int cur = 0;
    WOLFSSL_ASN1_TIME last;
    WOLFSSL_X509_CRL* best = NULL;
    WC_DECLARE_VAR(cert, DecodedCert, 1, 0);

    numCrls = wolfSSL_sk_X509_CRL_num(ctx->crls);
    if (numCrls <= 0)
        return WC_NO_ERR_TRACE(CRL_MISSING);

    WC_ALLOC_VAR_EX(cert, DecodedCert, 1, ctx->heap, DYNAMIC_TYPE_DCERT,
        return MEMORY_E);

    XMEMSET(&last, 0, sizeof(last));
    InitDecodedCert(cert, ctx->current_cert->derCert->buffer,
        ctx->current_cert->derCert->length, ctx->heap);
    /* The cert signature is verified by the CertManager. Only the issuer and
     * serial info is needed here. A parse error is final, not CRL_MISSING. */
    ret = ParseCertRelative(cert, CERT_TYPE, NO_VERIFY, ctx->store->cm, NULL);
    for (i = 0; ret == 0 && i < numCrls; i++) {
        WOLFSSL_X509_CRL* crl = wolfSSL_sk_X509_CRL_value(ctx->crls, i);

        if (crl != NULL) {
            ret = PickCertCRL(crl, cert, issuer, checkTime, &cur, &last);
            if (ret == 1) {
                best = crl;
                ret = 0;
            }
        }
    }
    if (ret == 0) {
        /* The store's cm verifies the CRL. The caller-owned crl is not
         * modified. */
        ret = (best == NULL) ? WC_NO_ERR_TRACE(CRL_MISSING) :
            CheckCertCRLFromCm(ctx->store->cm, best, cert, issuer, checkTime);
    }
    FreeDecodedCert(cert);
    WC_FREE_VAR_EX(cert, ctx->heap, DYNAMIC_TYPE_DCERT);

    return (ret == 0) ? WOLFSSL_SUCCESS : ret;
}
#endif /* HAVE_CRL */

/* Get the verification callback that applies to this context, or NULL when
 * none is installed. A callback set with wolfSSL_X509_STORE_CTX_set_verify_cb
 * takes precedence over one set on the store, matching OpenSSL.
 *
 * The context callback is settable in every OPENSSL_EXTRA build, so the
 * pathLen and INVALID_CA overrides driven from here are now reachable there
 * too, not just under OPENSSL_ALL or WOLFSSL_QT. */
static WOLFSSL_X509_STORE_CTX_verify_cb X509StoreGetVerifyCb(
        WOLFSSL_X509_STORE_CTX* ctx)
{
    if (ctx == NULL)
        return NULL;

    if (ctx->verify_cb != NULL)
        return ctx->verify_cb;

#if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    if (ctx->store != NULL)
        return ctx->store->verify_cb;
#endif

    return NULL;
}

/* Push x509 onto the ctx chain with its own reference, like OpenSSL.
 * The chain owns a reference to each of its certs.
 * Returns WOLFSSL_SUCCESS, MEMORY_E or WOLFSSL_FATAL_ERROR. */
static int X509StoreChainPush(WOLF_STACK_OF(WOLFSSL_X509)* chain,
                              WOLFSSL_X509* x509)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);

    if (x509 == NULL || wolfSSL_X509_up_ref(x509) != WOLFSSL_SUCCESS)
        return ret;
    ret = wolfSSL_sk_X509_push(chain, x509) > 0 ? WOLFSSL_SUCCESS :
        WC_NO_ERR_TRACE(MEMORY_E);
    if (ret != WOLFSSL_SUCCESS)
        wolfSSL_X509_free(x509);
    return ret;
}

/* Keeps e, when it is an error, in *err unless one is there: an internal
 * error of the chain checks. Returns e. */
static int X509StoreKeepErr(int* err, int e)
{
    if (err != NULL && *err == 0 && e < 0) {
        *err = e;
    }
    return e;
}

/* Returns 1 if `cert` (by pointer identity) is present in `stack`, else 0.
 * Used to keep a candidate that already failed verification off the reported
 * chain. */
static int X509StoreCertInStack(WOLF_STACK_OF(WOLFSSL_X509)* stack,
        WOLFSSL_X509* cert)
{
    int i;
    int num;

    if (stack == NULL || cert == NULL)
        return 0;

    /* Index by logical position like the other helpers in this file rather
     * than walking raw nodes. */
    num = wolfSSL_sk_X509_num(stack);
    for (i = 0; i < num; i++) {
        if (wolfSSL_sk_X509_value(stack, i) == cert)
            return 1;
    }

    return 0;
}

/* Returns 1 if cur and x509 have identical DER encodings, 0 otherwise. */
static int X509DerEquals(WOLFSSL_X509* cur, WOLFSSL_X509* x509)
{
    if (cur == NULL || cur->derCert == NULL ||
        x509 == NULL || x509->derCert == NULL) {
        return 0;
    }
    if (cur->derCert->length != x509->derCert->length)
        return 0;
    return XMEMCMP(cur->derCert->buffer, x509->derCert->buffer,
                   x509->derCert->length) == 0;
}

/* Returns 1 if x509's DER matches an entry in either origTrustedSk (the
 * trusted certs of the verification: the trusted stack of the ctx or the
 * certs added to the store) or in store->trusted.  Returns 0 otherwise.
 * NOTE: both are read without a lock, as at the issuer lookups, so an
 * X509_STORE must not be changed while it is used to verify. */
static int X509StoreCertIsTrusted(WOLFSSL_X509_STORE* store,
        WOLFSSL_X509* x509, WOLF_STACK_OF(WOLFSSL_X509)* origTrustedSk)
{
    int i;
    int n;

    if (x509 == NULL || x509->derCert == NULL)
        return 0;

    if (origTrustedSk != NULL) {
        n = wolfSSL_sk_X509_num(origTrustedSk);
        for (i = 0; i < n; i++) {
            if (X509DerEquals(wolfSSL_sk_X509_value(origTrustedSk, i), x509))
                return 1;
        }
    }

    if (store != NULL && store->trusted != NULL) {
        n = wolfSSL_sk_X509_num(store->trusted);
        for (i = 0; i < n; i++) {
            if (X509DerEquals(wolfSSL_sk_X509_value(store->trusted, i), x509))
                return 1;
        }
    }

    return 0;
}

/* Returns the store whose roots ctx trusts. As in OpenSSL, a trusted stack
 * replaces them. */
static WOLFSSL_X509_STORE* X509StoreRoots(WOLFSSL_X509_STORE_CTX* ctx)
{
    return (ctx->setTrustedSk != NULL) ? NULL : ctx->store;
}

/* As OpenSSL's check_extensions(): the pathLenConstraint of a CA bounds the
 * non-self-issued certs below it, the leaf not counted (RFC 5280 6.1.4 (l)
 * and (m)). The error is reported at that CA.
 * Returns WOLFSSL_SUCCESS, or WOLFSSL_FAILURE when the verify callback does
 * not accept an error. */
static int X509StoreCheckPathLen(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509_STORE_CTX_verify_cb verifyCb)
{
    int num;
    int i;
    word32 plen = 0;

    if (ctx == NULL || ctx->chain == NULL)
        return WOLFSSL_SUCCESS;

    num = wolfSSL_sk_X509_num(ctx->chain);
    for (i = 1; i < num; i++) {
        WOLFSSL_X509* x509 = wolfSSL_sk_X509_value(ctx->chain, i);

        if (x509 == NULL)
            continue;
        if (i > 1 && x509->isCa && x509->basicConstPlSet &&
                plen > x509->pathLength) {
            ctx->current_cert = x509;
            SetupStoreCtxError_ex(ctx,
                WOLFSSL_X509_V_ERR_PATH_LENGTH_EXCEEDED, i);
            if (verifyCb == NULL || verifyCb(0, ctx) != 1)
                return WOLFSSL_FAILURE;
        }
        if (wolfSSL_X509_NAME_cmp(&x509->issuer, &x509->subject) != 0)
            plen++;
    }

    return WOLFSSL_SUCCESS;
}

/* Returns 1 if X509_V_FLAG_PARTIAL_CHAIN is set on the param of ctx, as
 * OpenSSL reads it, otherwise 0. Init inherits the store's flags and
 * X509_STORE_CTX_set0_param() replaces them. ctx and ctx->store must be
 * non-NULL. */
static int X509StoreCertPartialChainEnabled(WOLFSSL_X509_STORE_CTX* ctx)
{
    WOLFSSL_X509_VERIFY_PARAM* param = ctx->param;

    /* Without a param, the store's, as init would inherit */
    if (param == NULL) {
        param = ctx->store->param;
    }
    return param != NULL && (param->flags & WOLFSSL_PARTIAL_CHAIN) != 0;
}

/* Returns 1 if x509 can issue certs as OpenSSL's X509_check_ca() decides,
 * with keyCertSign, as for a cert above the leaf. keyUsage, if present, must
 * allow cert signing and basicConstraints, if present, must say CA. Without
 * basicConstraints only the top cert of the chain can be a CA: a v1
 * self-signed cert or one with keyUsage. X509_V_FLAG_X509_STRICT drops that
 * exception, as OpenSSL does. */
static int X509StoreCertIsCa(WOLFSSL_X509_STORE_CTX* ctx, WOLFSSL_X509* x509,
        int top)
{
    if (x509->keyUsageSet && (x509->keyUsage & KEYUSE_KEY_CERT_SIGN) == 0) {
        return 0;
    }
    if (x509->basicConstSet) {
        return x509->isCa;
    }
    if (!top || (ctx->param != NULL &&
            (ctx->param->flags & WOLFSSL_X509_STRICT) != 0)) {
        return 0;
    }
    return x509->keyUsageSet || (x509->version == 1 &&
        wolfSSL_X509_check_issued(x509, x509) == WOLFSSL_X509_V_OK);
}

/* Returns 1 if x509, an issuer on the chain, need not be a CA: with
 * WOLFSSL_X509_STORE_ALLOW_NON_CA_INTERMEDIATE, an untrusted cert without
 * CA:TRUE. Otherwise 0. */
static int X509StoreNonCaAllowed(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509* x509, WOLF_STACK_OF(WOLFSSL_X509)* trustedSk)
{
#ifdef WOLFSSL_X509_STORE_ALLOW_NON_CA_INTERMEDIATE
    return !x509->isCa && X509StoreCertInStack(ctx->ctxIntermediates, x509) &&
        !X509StoreCertIsTrusted(X509StoreRoots(ctx), x509, trustedSk);
#else
    (void)ctx;
    (void)x509;
    (void)trustedSk;
    return 0;
#endif
}

/* Returns 1 if ca was loaded by the application. As in OpenSSL, whose store
 * holds only the certs added to it, a CA cached from a TLS peer's chain is
 * not a trust anchor. */
static int X509StoreCmCaLoaded(const Signer* ca)
{
    return ca != NULL && ca->type != WOLFSSL_CHAIN_CA &&
        ca->type != WOLFSSL_TEMP_CA;
}

/* Returns 1 when ret, of ParseCertRelative() with a cert manager or of
 * CheckCertSignaturePubKey(), is the result of verifying a cert, a
 * signature algorithm not supported included. The cert decoded before, so
 * another error is internal, as running out of memory. */
static int X509StoreVerifyResult(int ret)
{
    return ret == 0 || ret == WC_NO_ERR_TRACE(ASN_NO_SIGNER_E) ||
        ret == WC_NO_ERR_TRACE(ASN_SELF_SIGNED_E) ||
        ret == WC_NO_ERR_TRACE(ASN_SIG_CONFIRM_E) ||
        ret == WC_NO_ERR_TRACE(ASN_SIG_OID_E) ||
        ret == WC_NO_ERR_TRACE(ASN_SIG_KEY_E) ||
        ret == WC_NO_ERR_TRACE(ASN_SIG_HASH_E) ||
        ret == WC_NO_ERR_TRACE(ASN_UNKNOWN_OID_E) ||
        ret == WC_NO_ERR_TRACE(HASH_TYPE_E) ||
        ret == WC_NO_ERR_TRACE(NOT_COMPILED_IN) ||
        ret == WC_NO_ERR_TRACE(BUFFER_E) ||
        ret == WC_NO_ERR_TRACE(ASN_NAME_INVALID_E) ||
        ret == WC_NO_ERR_TRACE(ASN_PATHLEN_SIZE_E);
}

/* Verifies x509, dates aside, with a CA the application loaded into the cert
 * manager, which goes in *issuer when it has its DER and its key signed
 * x509. Returns 0 or the verify error. An internal error is kept in *err. */
static int X509StoreCmVerify(WOLFSSL_CERT_MANAGER* cm, WOLFSSL_X509* x509,
        WOLFSSL_X509** issuer, int* err)
{
    int ret;
    WC_DECLARE_VAR(cert, DecodedCert, 1, 0);

    WC_ALLOC_VAR_EX(cert, DecodedCert, 1, cm->heap, DYNAMIC_TYPE_DCERT,
        return X509StoreKeepErr(err, MEMORY_E));
    InitDecodedCert(cert, x509->derCert->buffer, x509->derCert->length,
        cm->heap);
    ret = ParseCertRelative(cert, CERT_TYPE, VERIFY_SKIP_DATE, cm, NULL);
    if (!X509StoreVerifyResult(ret)) {
        (void)X509StoreKeepErr(err, ret);
    }
    /* The CA verified it: as OpenSSL, its name constraints are checked on
     * the chain */
    if (ret == WC_NO_ERR_TRACE(ASN_NAME_INVALID_E)) {
        ret = 0;
    }
    if (ret == 0 && !X509StoreCmCaLoaded(cert->ca)) {
        ret = WC_NO_ERR_TRACE(ASN_NO_SIGNER_E);
    }
#ifdef WOLFSSL_SIGNER_DER_CERT
    /* A signer restored from a cert cache has no DER */
    if (ret == 0 && issuer != NULL && cert->ca->derCert != NULL) {
        WOLFSSL_X509* ca = NULL;

        if (wolfSSL_X509_d2i_ex(&ca, cert->ca->derCert->buffer,
                (int)cert->ca->derCert->length, cm->heap) == NULL) {
            (void)X509StoreKeepErr(err, WOLFSSL_FATAL_ERROR);
        }
        else if (X509StoreKeySigned(ca, x509, err)) {
            *issuer = ca;
            ca = NULL;
        }
        wolfSSL_X509_free(ca);
    }
#else
    (void)issuer;
#endif
    FreeDecodedCert(cert);
    WC_FREE_VAR_EX(cert, cm->heap, DYNAMIC_TYPE_DCERT);

    return ret;
}

/* Returns 1 if a CA the application loaded into the cert manager verifies
 * x509, dates aside, otherwise 0. An internal error is kept in *err. */
static int X509StoreCmHasIssuer(WOLFSSL_CERT_MANAGER* cm, WOLFSSL_X509* x509,
        int* err)
{
    return X509StoreCmVerify(cm, x509, NULL, err) == 0;
}

/* Returns 1 if x509 is a self-signed CA the application loaded into the cert
 * manager of a store that keeps its CAs only there, as an SSL_CTX's store: the
 * CA has its key and, when the CA keeps its DER, the same DER. Otherwise 0.
 * An internal error is kept in *err. */
static int X509StoreCmHasCert(WOLFSSL_X509_STORE_CTX* ctx, WOLFSSL_X509* x509,
        int* err)
{
    WOLFSSL_CERT_MANAGER* cm = ctx->store->cm;
    int ret;
    WC_DECLARE_VAR(cert, DecodedCert, 1, 0);

    if (ctx->setTrustedSk != NULL || ctx->store->trusted != NULL ||
            x509->derCert == NULL) {
        return 0;
    }
    WC_ALLOC_VAR_EX(cert, DecodedCert, 1, cm->heap, DYNAMIC_TYPE_DCERT,
        { (void)X509StoreKeepErr(err, MEMORY_E); return 0; });
    InitDecodedCert(cert, x509->derCert->buffer, x509->derCert->length,
        cm->heap);
    ret = ParseCertRelative(cert, CERT_TYPE, VERIFY_SKIP_DATE, cm, NULL);
    if (!X509StoreVerifyResult(ret)) {
        (void)X509StoreKeepErr(err, ret);
    }
    ret = ret == 0 && X509StoreCmCaLoaded(cert->ca);
#ifdef WOLFSSL_SIGNER_DER_CERT
    if (ret && cert->ca != NULL && cert->ca->derCert != NULL) {
        ret = cert->ca->derCert->length == x509->derCert->length &&
            XMEMCMP(cert->ca->derCert->buffer, x509->derCert->buffer,
                x509->derCert->length) == 0;
    }
#endif
    FreeDecodedCert(cert);
    WC_FREE_VAR_EX(cert, cm->heap, DYNAMIC_TYPE_DCERT);

    return ret;
}

#if defined(SESSION_CERTS) && defined(KEEP_PEER_CERT)
/* Returns 1 if ca, above x509 on a chain, is the CA the application loaded
 * into the cert manager that verifies x509, dates aside: the same cert, by
 * its DER. Otherwise 0. */
static int X509StoreCmIsIssuer(WOLFSSL_CERT_MANAGER* cm, WOLFSSL_X509* ca,
        WOLFSSL_X509* x509)
{
    int err = 0;
    int ret = 0;
    WOLFSSL_X509* issuer = NULL;

    if (cm == NULL || ca == NULL || x509 == NULL || x509->derCert == NULL) {
        return 0;
    }
    if (X509StoreCmVerify(cm, x509, &issuer, &err) == 0 && err == 0) {
        ret = X509DerEquals(issuer, ca);
    }
    wolfSSL_X509_free(issuer);

    return ret;
}
#endif

/* As OpenSSL's check_chain_extensions(): every cert above the leaf issues
 * the one below it, so it must be a CA that may sign certs. num is the
 * number of chain certs to check.
 * Returns WOLFSSL_SUCCESS, or WOLFSSL_FAILURE when the verify callback does
 * not accept an error. */
static int X509StoreCheckChainCa(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509_STORE_CTX_verify_cb verifyCb,
        WOLF_STACK_OF(WOLFSSL_X509)* trustedSk, int num)
{
    int i;

    for (i = 1; i < num; i++) {
        WOLFSSL_X509* x509 = wolfSSL_sk_X509_value(ctx->chain, i);

        if (x509 == NULL || X509StoreNonCaAllowed(ctx, x509, trustedSk) ||
                X509StoreCertIsCa(ctx, x509, i == num - 1)) {
            continue;
        }
        ctx->current_cert = x509;
        SetupStoreCtxError_ex(ctx, WOLFSSL_X509_V_ERR_INVALID_CA, i);
        if (verifyCb == NULL || verifyCb(0, ctx) != 1) {
            return WOLFSSL_FAILURE;
        }
    }
    return WOLFSSL_SUCCESS;
}

/* As OpenSSL's find_issuer(), picks from certs a cert that issued x, its
 * names and key ids matching: the first one valid at the verification time,
 * else the one that expires last, as *best when it expires later. Its key
 * is not checked. With skipChain, certs on the chain are not picked.
 * Failing closed, a cert without its DER is not picked, so that every cert
 * on the chain has it and is checked.
 * Returns 1 when *best is valid at the verification time, else 0. */
static int X509StorePickIssuer(WOLFSSL_X509_STORE_CTX* ctx,
        WOLF_STACK_OF(WOLFSSL_X509)* certs, WOLFSSL_X509* x, int skipChain,
        WOLFSSL_X509** best)
{
    int i;

    for (i = 0; i < wolfSSL_sk_X509_num(certs); i++) {
        WOLFSSL_X509* ca = wolfSSL_sk_X509_value(certs, i);

        if (ca == NULL || ca->derCert == NULL || (skipChain &&
                X509StoreCertInStack(ctx->chain, ca)) ||
                !X509StoreIssued(ca, x)) {
            continue;
        }
    #ifndef NO_ASN_TIME
        if (X509StoreCheckCertDate(ctx, ca) != WOLFSSL_SUCCESS) {
            if (*best == NULL || wolfSSL_ASN1_TIME_compare(&ca->notAfter,
                    &(*best)->notAfter) > 0) {
                *best = ca;
            }
            continue;
        }
    #endif
        *best = ca;
        return 1;
    }
    return 0;
}

/* Returns the trusted cert that issued x, as OpenSSL's
 * X509_STORE_CTX_get1_issuer() picks it: certs on the chain included. As in
 * OpenSSL, a trusted stack replaces the store's trusted certs. */
static WOLFSSL_X509* X509StoreFindTrusted(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509* x)
{
    WOLFSSL_X509* ca = NULL;

    (void)X509StorePickIssuer(ctx, (ctx->setTrustedSk != NULL) ?
        ctx->setTrustedSk : ctx->store->added, x, 0, &ca);
    return ca;
}

/* As OpenSSL looks for an alternate chain: the highest untrusted cert below
 * the top untrusted one, the numUntrusted certs from the leaf being
 * untrusted, that a trusted cert or a CA of the cert manager issued.
 * Returns its depth, or -1 when there is none. *alt is that trusted cert,
 * NULL for a CA of the cert manager. An internal error is kept in *err. */
static int X509StoreTrustedAlt(WOLFSSL_X509_STORE_CTX* ctx, int numUntrusted,
        WOLFSSL_X509** alt, int* err)
{
    int i;

    for (i = numUntrusted - 2; i >= 0; i--) {
        WOLFSSL_X509* x = wolfSSL_sk_X509_value(ctx->chain, i);

        *alt = X509StoreFindTrusted(ctx, x);
        if (*alt != NULL || (ctx->setTrustedSk == NULL &&
                X509StoreCmHasIssuer(ctx->store->cm, x, err))) {
            return i;
        }
    }
    *alt = NULL;
    return -1;
}

/* As OpenSSL, an internal error is not a verify error: the verify callback
 * is not asked and the verification fails, with X509_V_ERR_OUT_OF_MEM when
 * memory ran out, else X509_V_ERR_UNSPECIFIED.
 * Returns WOLFSSL_FAILURE. */
static int X509StoreFatal(WOLFSSL_X509_STORE_CTX* ctx, int err)
{
    ctx->error = (err == WC_NO_ERR_TRACE(MEMORY_E) ||
            err == WC_NO_ERR_TRACE(MEMORY_ERROR)) ?
        WOLFSSL_X509_V_ERR_OUT_OF_MEM : WOLFSSL_X509_V_ERR_UNSPECIFIED;
    return WOLFSSL_FAILURE;
}

/* Records err for x at depth and asks the verify callback.
 * Returns 1 when the callback accepts the error. */
static int X509StoreReport(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509_STORE_CTX_verify_cb verifyCb, WOLFSSL_X509* x, int err,
        int depth)
{
    ctx->current_cert = x;
    SetupStoreCtxError_ex(ctx, err, depth);
    return verifyCb != NULL && verifyCb(0, ctx) == 1;
}

/* As OpenSSL's check_auth_level(): the key of each issuer, the trust anchor
 * included, must meet the cert manager's minimum CA key size.
 * Returns WOLFSSL_SUCCESS, or WOLFSSL_FAILURE when the verify callback does
 * not accept an error. */
static int X509StoreCheckChainKeys(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509_STORE_CTX_verify_cb verifyCb, int num)
{
    int i;

    for (i = 1; i < num; i++) {
        WOLFSSL_X509* x509 = wolfSSL_sk_X509_value(ctx->chain, i);

        if (x509 != NULL && CheckCAKeySize(ctx->store->cm,
                (word32)x509->pubKeyOID, x509->pubKey.buffer,
                x509->pubKey.length) != 0 &&
                !X509StoreReport(ctx, verifyCb, x509,
                    WOLFSSL_X509_V_ERR_CA_KEY_TOO_SMALL, i)) {
            return WOLFSSL_FAILURE;
        }
    }
    return WOLFSSL_SUCCESS;
}

/* As OpenSSL's internal_verify(), top down. sigFail holds the certs whose
 * issuer did not sign them. Returns WOLFSSL_SUCCESS or WOLFSSL_FAILURE. */
static int X509StoreCheckChainCerts(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509_STORE_CTX_verify_cb verifyCb,
        WOLF_STACK_OF(WOLFSSL_X509)* trustedSk, int num, int noIssuer,
        WOLF_STACK_OF(WOLFSSL_X509)* sigFail)
{
    int i = num - 1;

    if (noIssuer && !X509StoreCertPartialChainEnabled(ctx)) {
        if (i > 0) {
            i--;
        }
        else if (!X509StoreReport(ctx, verifyCb,
                wolfSSL_sk_X509_value(ctx->chain, 0),
                WOLFSSL_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE, 0)) {
            return WOLFSSL_FAILURE;
        }
    }
    for (; i >= 0; i--) {
        WOLFSSL_X509* x509 = wolfSSL_sk_X509_value(ctx->chain, i);
        WOLFSSL_X509* up = (i + 1 < num) ?
            wolfSSL_sk_X509_value(ctx->chain, i + 1) : NULL;
    #ifndef NO_ASN_TIME
        int ret;
    #endif

        /* RFC 5280 6.1.4 (n): the issuer's keyUsage must allow keyCertSign */
        if (up != NULL && up->keyUsageSet &&
                (up->keyUsage & KEYUSE_KEY_CERT_SIGN) == 0 &&
                !X509StoreNonCaAllowed(ctx, up, trustedSk) &&
                !X509StoreReport(ctx, verifyCb, up,
                    WOLFSSL_X509_V_ERR_KEYUSAGE_NO_CERTSIGN, i + 1)) {
            return WOLFSSL_FAILURE;
        }
        if (X509StoreCertInStack(sigFail, x509) &&
                !X509StoreReport(ctx, verifyCb, x509,
                    WOLFSSL_X509_V_ERR_CERT_SIGNATURE_FAILURE, i)) {
            return WOLFSSL_FAILURE;
        }
    #ifndef NO_ASN_TIME

        if (x509 != NULL) {
            ret = X509StoreCheckCertDate(ctx, x509);
            if (ret != WOLFSSL_SUCCESS &&
                    !X509StoreReport(ctx, verifyCb, x509, ret, i)) {
                return WOLFSSL_FAILURE;
            }
        }
    #endif
        ctx->current_cert = x509;
        ctx->error_depth = i;
        if (verifyCb != NULL && verifyCb(1, ctx) != 1) {
            return WOLFSSL_FAILURE;
        }
    }
    return WOLFSSL_SUCCESS;
}

#ifndef IGNORE_NAME_CONSTRAINTS
/* As OpenSSL's check_name_constraints(): the names of each cert, but a
 * self-issued one above the leaf, meet the name constraints of every cert
 * above it on the chain, the anchor included.
 * Returns WOLFSSL_SUCCESS, or WOLFSSL_FAILURE when the verify callback does
 * not accept an error. */
static int X509StoreCheckChainNames(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509_STORE_CTX_verify_cb verifyCb, int num)
{
    int i;
    int j;
    int ret;

    for (i = num - 1; i >= 0; i--) {
        WOLFSSL_X509* x509 = wolfSSL_sk_X509_value(ctx->chain, i);

        if (x509 == NULL || (i > 0 &&
                wolfSSL_X509_NAME_cmp(&x509->issuer, &x509->subject) == 0)) {
            continue;
        }
        for (j = num - 1; j > i; j--) {
            WOLFSSL_X509* ca = wolfSSL_sk_X509_value(ctx->chain, j);
            int violation = 0;

            if (ca == NULL || (ca->permittedNames == NULL &&
                     ca->excludedNames == NULL && !ca->nameConstraintCrit)) {
                continue;
            }
            ret = CheckCertNameConstraints(ca->derCert->buffer,
                ca->derCert->length, x509->derCert->buffer,
                x509->derCert->length, i == 0, ctx->heap, &violation);
            if (ret != 0) {
                return X509StoreFatal(ctx, ret);
            }
            if (violation != 0 && !X509StoreReport(ctx, verifyCb, x509,
                    (violation == NC_VIOLATION_EXCLUDED) ?
                    WOLFSSL_X509_V_ERR_EXCLUDED_VIOLATION :
                    (violation == NC_VIOLATION_PERMITTED) ?
                    WOLFSSL_X509_V_ERR_PERMITTED_VIOLATION :
                    WOLFSSL_X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE, i)) {
                return WOLFSSL_FAILURE;
            }
        }
    }
    return WOLFSSL_SUCCESS;
}
#endif /* IGNORE_NAME_CONSTRAINTS */

#ifdef HAVE_CRL
/* As OpenSSL's get_crl_delta(), checks the cert with a CRL of up, its issuer,
 * of the ctx, else of the store. staleOk and anyKeyUsage accept one out of
 * date or without cRLSign. Returns WOLFSSL_SUCCESS or the CRL error. */
static int X509StoreCheckCertCrls(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509* up, int staleOk, int anyKeyUsage)
{
    int ret = WC_NO_ERR_TRACE(CRL_MISSING);
    Signer issuer;
#ifndef NO_ASN_TIME
    time_t t;
    const time_t* checkTime = (!staleOk && X509StoreCheckTime(ctx, &t)) ?
        &t : NULL;
#else
    const time_t* checkTime = NULL;

    (void)staleOk;
#endif

    XMEMSET(&issuer, 0, sizeof(issuer));
    issuer.publicKey = up->pubKey.buffer;
    issuer.pubKeySize = up->pubKey.length;
    issuer.keyOID = (word32)up->pubKeyOID;
    /* Without the extension any key usage is allowed */
    issuer.keyUsage = (up->keyUsageSet && !anyKeyUsage) ?
        up->keyUsage : 0xFFFF;
#ifndef NO_SKID
    /* Its subject key id, if any, picks out its CRLs */
    if (up->subjKeyIdSet && up->subjKeyId != NULL &&
            GetHashId(up->subjKeyId, (int)up->subjKeyIdSz,
                issuer.subjectKeyIdHash,
                HashIdAlg((word32)up->sigOID)) != 0) {
        XMEMSET(issuer.subjectKeyIdHash, 0,
            sizeof(issuer.subjectKeyIdHash));
    }
#endif
    if (ctx->crls != NULL) {
        ret = X509StoreCheckCtxCrls(ctx, &issuer, checkTime);
    }
    if (ret == WC_NO_ERR_TRACE(CRL_MISSING) && ctx->store->cm->crl != NULL) {
        ret = X509StoreCheckStoreCrl(ctx, &issuer, checkTime);
    }
    return ret;
}
#endif /* HAVE_CRL */

/* As OpenSSL's check_revocation(): the leaf, or every cert with check-all.
 * Check-all of the cert manager, as TLS, leaves the trust anchor out.
 * Returns WOLFSSL_SUCCESS, or WOLFSSL_FAILURE when the verify callback does
 * not accept an error. */
static int X509StoreCheckChainCrls(WOLFSSL_X509_STORE_CTX* ctx,
        WOLFSSL_X509_STORE_CTX_verify_cb verifyCb, int num, int noIssuer)
{
    unsigned long flags = (ctx->param != NULL) ? ctx->param->flags : 0;
#ifdef HAVE_CRL
    WOLFSSL_CERT_MANAGER* cm = ctx->store->cm;
    /* Enabled on the cert manager, or as OpenSSL by the verify param */
    int check = cm->crlEnabled ||
        (flags & WOLFSSL_X509_V_FLAG_CRL_CHECK) != 0;
    int checkAll = (cm->crlEnabled && cm->crlCheckAll) ||
        (flags & WOLFSSL_X509_V_FLAG_CRL_CHECK_ALL) != 0;
#else
    int check = (flags & WOLFSSL_X509_V_FLAG_CRL_CHECK) != 0;
    int checkAll = (flags & WOLFSSL_X509_V_FLAG_CRL_CHECK_ALL) != 0;
#endif
    int i;
    int ret;

    for (i = 0; check && (i == 0 || checkAll) && i < num; i++) {
        WOLFSSL_X509* x509 = wolfSSL_sk_X509_value(ctx->chain, i);
        WOLFSSL_X509* up = NULL;

        if (i < num - 1) {
            up = wolfSSL_sk_X509_value(ctx->chain, i + 1);
        }
        else if (!noIssuer && i > 0 &&
                (flags & WOLFSSL_X509_V_FLAG_CRL_CHECK_ALL) == 0) {
            break;
        }
        else if (!noIssuer && X509StoreIssued(x509, x509)) {
            /* As OpenSSL, a self-issued top cert has its own CRLs. Another
             * has none. */
            up = x509;
        }
        ctx->current_cert = x509;
        ret = WC_NO_ERR_TRACE(CRL_MISSING);
    #ifdef HAVE_CRL
        if (up != NULL) {
            int anyKeyUsage = 0;

            ret = X509StoreCheckCertCrls(ctx, up, 0, 0);
            /* As OpenSSL, a CRL of an issuer without cRLSign is reported.
             * Once that is accepted, the CRL is used. */
            if (ret == WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E)) {
                if (!X509StoreReport(ctx, verifyCb, ctx->current_cert,
                        WOLFSSL_X509_V_ERR_KEYUSAGE_NO_CRL_SIGN, i)) {
                    return WOLFSSL_FAILURE;
                }
                anyKeyUsage = 1;
                ret = X509StoreCheckCertCrls(ctx, up, 0, anyKeyUsage);
            }
            /* As OpenSSL, once its error is accepted a CRL out of date is
             * used */
            if (ret == WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E) ||
                    ret == WC_NO_ERR_TRACE(CRL_CERT_DATE_ERR)) {
                if (!X509StoreReport(ctx, verifyCb, ctx->current_cert,
                        (ret == WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E)) ?
                        WOLFSSL_X509_V_ERR_CRL_NOT_YET_VALID :
                        WOLFSSL_X509_V_ERR_CRL_HAS_EXPIRED, i)) {
                    return WOLFSSL_FAILURE;
                }
                ret = X509StoreCheckCertCrls(ctx, up, 1, anyKeyUsage);
            }
        }
    #else
        (void)up;
    #endif
        /* Any other error is internal */
        if (ret != WOLFSSL_SUCCESS && ret != WC_NO_ERR_TRACE(CRL_MISSING) &&
                ret != WC_NO_ERR_TRACE(CRL_CERT_REVOKED) &&
                ret != WC_NO_ERR_TRACE(ASN_CRL_CONFIRM_E)) {
            return X509StoreFatal(ctx, ret);
        }
        /* A CRL that does not verify is not used. Its entries are not
         * checked, so failing closed its error is final. */
        if (ret != WOLFSSL_SUCCESS &&
                (!X509StoreReport(ctx, verifyCb, ctx->current_cert, ret, i) ||
                 ret == WC_NO_ERR_TRACE(ASN_CRL_CONFIRM_E))) {
            return WOLFSSL_FAILURE;
        }
    }
    return WOLFSSL_SUCCESS;
}

/* Verifies certificate chain using WOLFSSL_X509_STORE_CTX
 * returns 1 on success or <= 0 on failure.
 * Builds and checks the chain as OpenSSL's build_chain() and verify_chain(),
 * failing closed: the first issuer found is final, and an alternate chain is
 * taken only when its trusted cert is the same cert. A CA of the cert
 * manager is trusted and, as in the handshake, needs no issuer there. */
int wolfSSL_X509_verify_cert(WOLFSSL_X509_STORE_CTX* ctx)
{
    int ret = WOLFSSL_SUCCESS;
    int depth;
    int num;
    int trustedFirst;
    int trustedSeen = 0;
    int fromTrusted = 0;
    int numUntrusted = 1;
    int noIssuer = 0;
    int cmRet;
    int fromCm = 0;
    int err = 0;
    WOLF_STACK_OF(WOLFSSL_X509)* sigFail = NULL;
    WOLFSSL_X509* x;
    WOLFSSL_X509* issuer;
    WOLFSSL_X509* cmIssuer = NULL;
    WOLFSSL_X509* orig;
    WOLF_STACK_OF(WOLFSSL_X509)* trustedSk;
    WOLFSSL_X509_STORE_CTX_verify_cb verifyCb;

    WOLFSSL_ENTER("wolfSSL_X509_verify_cert");

    if (ctx == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }
    if (ctx->store == NULL || ctx->store->cm == NULL ||
            ctx->current_cert == NULL || ctx->current_cert->derCert == NULL) {
        ctx->error = WOLFSSL_X509_V_ERR_UNSPECIFIED;
        return WOLFSSL_FATAL_ERROR;
    }

    verifyCb = X509StoreGetVerifyCb(ctx);
    /* Without a param, the default of init */
    trustedFirst = ctx->param == NULL ||
        (ctx->param->flags & WOLFSSL_TRUSTED_FIRST) != 0;
    trustedSk = (ctx->setTrustedSk != NULL) ? ctx->setTrustedSk :
        ctx->store->certs;
    depth = (ctx->param != NULL) ? ctx->param->depth :
        WOLFSSL_X509_STORE_DEFAULT_MAX_DEPTH;
    orig = ctx->current_cert;

    if (ctx->chain != NULL) {
        wolfSSL_sk_X509_pop_free(ctx->chain, NULL);
    }
    ctx->chain = wolfSSL_sk_X509_new_null();
    if (ctx->chain == NULL) {
        err = MEMORY_E;
        goto exit;
    }
    x = orig;
    if (X509StoreKeepErr(&err, X509StoreChainPush(ctx->chain, x)) !=
            WOLFSSL_SUCCESS) {
        goto exit;
    }
    /* A negative depth, unset included, leaves no room for any chain. As
     * OpenSSL, the callback is told; failing closed, the error is final. */
    if (depth < 0) {
        (void)X509StoreReport(ctx, verifyCb, x,
            WOLFSSL_X509_V_ERR_CERT_CHAIN_TOO_LONG, 0);
        ret = WOLFSSL_FAILURE;
        goto exit;
    }
    for (;;) {
        /* As OpenSSL, self-signed by names and key ids, key not checked */
        int selfSigned = X509StoreIssued(x, x);
        /* As in OpenSSL, a cert found among the trusted certs, or a
         * self-signed cert that is the trusted cert picked as its issuer */
        int trusted = fromTrusted || (selfSigned &&
            X509DerEquals(X509StoreFindTrusted(ctx, x), x));
        WOLFSSL_X509* alt = NULL;
        int altDepth = -1;

        num = wolfSSL_sk_X509_num(ctx->chain);
        trustedSeen |= trusted;
        /* As in OpenSSL, the self-signature of a trusted cert is not
         * checked */
        if (trusted && (selfSigned || X509StoreCertPartialChainEnabled(ctx))) {
            break;
        }
        /* A self-signed CA of the cert manager is a trust anchor */
        if (selfSigned && X509StoreCmHasCert(ctx, x, &err)) {
            break;
        }

        issuer = NULL;
        /* 1 until the cert manager is asked, once, for x */
        cmRet = 1;
        fromTrusted = 0;
        if (!selfSigned) {
            /* The cert manager's CAs are trusted, searched after the trusted
             * certs */
            if (trustedSeen || trustedFirst) {
                issuer = X509StoreFindTrusted(ctx, x);
                fromTrusted = issuer != NULL;
                if (issuer == NULL && ctx->setTrustedSk == NULL) {
                    cmRet = X509StoreCmVerify(ctx->store->cm, x, &cmIssuer,
                        &err);
                }
            }
            if (issuer == NULL && cmRet != 0 && !trustedSeen) {
                (void)X509StorePickIssuer(ctx, ctx->ctxIntermediates, x, 1,
                    &issuer);
                if (issuer != NULL) {
                    numUntrusted++;
                }
                else if (!trustedFirst) {
                    issuer = X509StoreFindTrusted(ctx, x);
                    fromTrusted = issuer != NULL;
                    if (issuer == NULL && ctx->setTrustedSk == NULL) {
                        cmRet = X509StoreCmVerify(ctx->store->cm, x,
                            &cmIssuer, &err);
                    }
                }
            }
        }
        /* wolfSSL trusts a CA of the cert manager without an issuer there */
        if (err == 0 && fromCm && issuer == NULL && cmRet != 0) {
            if (cmRet == 1) {
                cmRet = X509StoreCmVerify(ctx->store->cm, x, NULL, &err);
            }
            if (cmRet == WC_NO_ERR_TRACE(ASN_NO_SIGNER_E) ||
                    cmRet == WC_NO_ERR_TRACE(ASN_SELF_SIGNED_E)) {
                break;
            }
        }
        if (err != 0) {
            goto exit;
        }
        /* The leaf and the trust anchor do not count against the depth */
        if (!selfSigned && num - 1 > depth) {
            (void)X509StoreReport(ctx, verifyCb, x,
                WOLFSSL_X509_V_ERR_CERT_CHAIN_TOO_LONG, num - 1);
            ret = WOLFSSL_FAILURE;
            goto exit;
        }
        /* A CA of the cert manager is a trusted cert. Without its DER it
         * cannot go on the chain: fail closed as without an issuer. */
        fromCm = cmIssuer != NULL;
        if (fromCm) {
            x = cmIssuer;
            cmIssuer = NULL;
            (void)X509StoreKeepErr(&err, X509StoreChainPush(ctx->chain, x));
            /* The chain holds x unless err */
            wolfSSL_X509_free(x);
            if (err != 0) {
                goto exit;
            }
            fromTrusted = 1;
            continue;
        }
        /* OpenSSL takes a trusted issuer on the chain again, until the chain
         * is too long */
        if (issuer != NULL && X509StoreCertInStack(ctx->chain, issuer)) {
            (void)X509StoreReport(ctx, verifyCb, x,
                WOLFSSL_X509_V_ERR_CERT_CHAIN_TOO_LONG, num - 1);
            ret = WOLFSSL_FAILURE;
            goto exit;
        }
        if (issuer == NULL) {
            altDepth = X509StoreTrustedAlt(ctx, numUntrusted, &alt, &err);
            /* Failing closed, OpenSSL's alternate chain is only taken when
             * its trusted cert is the untrusted cert above, the same cert */
            if (altDepth >= 0 && X509DerEquals(alt,
                    wolfSSL_sk_X509_value(ctx->chain, altDepth + 1))) {
                while (wolfSSL_sk_X509_num(ctx->chain) > altDepth + 1) {
                    wolfSSL_X509_free(wolfSSL_sk_X509_pop(ctx->chain));
                }
                while (wolfSSL_sk_X509_num(sigFail) > 0 &&
                        !X509StoreCertInStack(ctx->chain,
                            wolfSSL_sk_X509_value(sigFail,
                                wolfSSL_sk_X509_num(sigFail) - 1))) {
                    (void)wolfSSL_sk_X509_pop(sigFail);
                }
                numUntrusted = altDepth + 1;
                issuer = alt;
                fromTrusted = 1;
            }
        }
        if (err != 0) {
            goto exit;
        }
        /* As OpenSSL's last resort, a trusted leaf ends a partial chain
         * without a trusted cert */
        if (issuer == NULL && !trustedSeen && altDepth < 0 &&
                X509StoreCertPartialChainEnabled(ctx) &&
                X509StoreCertIsTrusted(X509StoreRoots(ctx), orig,
                    trustedSk)) {
            noIssuer = !selfSigned;
            break;
        }
        if (issuer == NULL && selfSigned) {
            if (!X509StoreReport(ctx, verifyCb, x, (num == 1) ?
                    WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT :
                    WOLFSSL_X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN, num - 1) ||
                    altDepth >= 0) {
                ret = WOLFSSL_FAILURE;
                goto exit;
            }
            break;
        }
        if (issuer == NULL) {
            if (!X509StoreReport(ctx, verifyCb, x, trusted ?
                    WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT :
                    WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                    num - 1) || altDepth >= 0) {
                ret = WOLFSSL_FAILURE;
                goto exit;
            }
            noIssuer = 1;
            break;
        }
        x = wolfSSL_sk_X509_value(ctx->chain,
            wolfSSL_sk_X509_num(ctx->chain) - 1);
        /* Its signature failure is reported with the chain's signatures */
        if (!X509StoreCertInStack(sigFail, x) &&
                !X509StoreKeySigned(issuer, x, &err) && err == 0 &&
                ((sigFail == NULL &&
                (sigFail = wolfSSL_sk_X509_new_null()) == NULL) ||
                wolfSSL_sk_X509_push(sigFail, x) <= 0)) {
            err = MEMORY_E;
        }
        if (err != 0 || X509StoreKeepErr(&err,
                X509StoreChainPush(ctx->chain, issuer)) != WOLFSSL_SUCCESS) {
            goto exit;
        }
        x = issuer;
    }
    num = wolfSSL_sk_X509_num(ctx->chain);

    ret = X509StoreCheckChainCa(ctx, verifyCb, trustedSk, num);
    if (ret == WOLFSSL_SUCCESS) {
        ret = X509StoreCheckPathLen(ctx, verifyCb);
    }
    if (ret == WOLFSSL_SUCCESS) {
        ret = X509StoreCheckChainKeys(ctx, verifyCb, num);
    }

    /* Host and IP of the leaf, reported as OpenSSL's check_id_error() */
    if (ret == WOLFSSL_SUCCESS && ctx->param != NULL &&
            ctx->param->hostName[0] != '\0' &&
            wolfSSL_X509_check_host(orig, ctx->param->hostName,
                XSTRLEN(ctx->param->hostName), ctx->param->hostFlags,
                NULL) != WOLFSSL_SUCCESS &&
            !X509StoreReport(ctx, verifyCb, orig,
                WOLFSSL_X509_V_ERR_HOSTNAME_MISMATCH, 0)) {
        ret = WOLFSSL_FAILURE;
    }
    if (ret == WOLFSSL_SUCCESS && ctx->param != NULL &&
            ctx->param->ipasc[0] != '\0' &&
            wolfSSL_X509_check_ip_asc(orig, ctx->param->ipasc,
                ctx->param->hostFlags) != WOLFSSL_SUCCESS &&
            !X509StoreReport(ctx, verifyCb, orig,
                WOLFSSL_X509_V_ERR_IP_ADDRESS_MISMATCH, 0)) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = X509StoreCheckChainCrls(ctx, verifyCb, num, noIssuer);
    }
    if (ret == WOLFSSL_SUCCESS) {
        ret = X509StoreCheckChainCerts(ctx, verifyCb, trustedSk, num,
            noIssuer, sigFail);
    }
#ifndef IGNORE_NAME_CONSTRAINTS
    if (ret == WOLFSSL_SUCCESS) {
        ret = X509StoreCheckChainNames(ctx, verifyCb, num);
    }
#endif

exit:
    wolfSSL_X509_free(cmIssuer);
    wolfSSL_sk_X509_free(sigFail);
    if (err != 0) {
        ret = X509StoreFatal(ctx, err);
    }
    if (orig != NULL) {
        ctx->current_cert = orig;
    }
    /* Every failure must be reportable through X509_STORE_CTX_get_error() */
    if (ret != WOLFSSL_SUCCESS && ctx->error == WOLFSSL_X509_V_OK) {
        ctx->error = WOLFSSL_X509_V_ERR_UNSPECIFIED;
    }

    return ret == WOLFSSL_SUCCESS ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE;
}

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
WOLFSSL_X509* wolfSSL_X509_STORE_CTX_get_current_cert(
                                            WOLFSSL_X509_STORE_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_get_current_cert");
    if (ctx)
        return ctx->current_cert;
    return NULL;
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
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */


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
        if (ctx)
            return ctx->error_depth;
        return WOLFSSL_FATAL_ERROR;
    }

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
    if (ctx == NULL) {
        return;
    }
    if (flags & WOLFSSL_PARTIAL_CHAIN) {
        ctx->flags |= WOLFSSL_PARTIAL_CHAIN;
    }
    /* As in OpenSSL, the flags go on the verify param too */
    (void)wolfSSL_X509_VERIFY_PARAM_set_flags(ctx->param, flags);
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

#if defined(WOLFSSL_APACHE_HTTPD) || defined(OPENSSL_EXTRA)
/* Set the maximum number of intermediate CAs allowed between the leaf and the
 * trust anchor; neither the leaf nor the anchor counts, so 0 allows none.
 * A negative depth rejects every chain. X509_STORE_CTX_init() resets
 * the depth, so call this after init. */
void wolfSSL_X509_STORE_CTX_set_depth(WOLFSSL_X509_STORE_CTX* ctx, int depth)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_set_depth");
    if (ctx != NULL) {
        wolfSSL_X509_VERIFY_PARAM_set_depth(ctx->param, depth);
    }
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
        int lastIdx = -1;
        WOLFSSL_X509_CHAIN* c = ctx->sesChain;
        WOLFSSL_STACK*     sk = wolfSSL_sk_new_node(ctx->heap);

        if (sk == NULL)
            return NULL;

        for (i = 0; i < c->count; i++) {
            WOLFSSL_X509* x509;

            /* A certificate too large to keep leaves its slot empty. An
             * issuer must never slide into the leaf's slot. */
            if (c->certs[i].length == 0) {
                if (i == 0) {
                    WOLFSSL_MSG("Peer cert missing from session chain");
                    error = 1;
                    break;
                }
                continue;
            }

            x509 = wolfSSL_get_chain_X509(c, i);
            if (x509 == NULL) {
                WOLFSSL_MSG("Unable to get x509 from chain");
                error = 1;
                break;
            }

            if (wolfSSL_sk_X509_push(sk, x509) <= 0) {
                WOLFSSL_MSG("Unable to load x509 into stack");
                wolfSSL_X509_free(x509);
                x509 = NULL;
                error = 1;
                break;
            }
            lastIdx = i;
        }

#if defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) || \
    defined(OPENSSL_EXTRA)
        /* add CA used to verify top of chain to the list */
        if (!error && lastIdx >= 0) {
            WOLFSSL_X509* x509 = wolfSSL_get_chain_X509(c, lastIdx);
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
                            wolfSSL_X509_free(issuer);
                            issuer = NULL;
                        }
                    }
                    else {
                        WOLFSSL_MSG("Certificate is self signed");
                        wolfSSL_X509_free(issuer);
                        issuer = NULL;
                    }
                }
                else {
                    WOLFSSL_MSG("Could not find CA for certificate");
                }
            }
            wolfSSL_X509_free(x509);
            x509 = NULL;
        }
#endif
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
    return wolfSSL_X509_chain_up_ref(ref);
}

#ifndef NO_WOLFSSL_STUB
WOLFSSL_X509_STORE_CTX *wolfSSL_X509_STORE_CTX_get0_parent_ctx(
                                                   WOLFSSL_X509_STORE_CTX *ctx)
{
    (void)ctx;
    WOLFSSL_STUB("wolfSSL_X509_STORE_CTX_get0_parent_ctx");
    return NULL;
}
#endif

/* Returns the first cert in certs with the subject name. */
static WOLFSSL_X509* X509StoreFindBySubject(WOLFSSL_STACK* certs,
    const WOLFSSL_X509_NAME* name)
{
    int i;

    for (i = 0; i < wolfSSL_sk_X509_num(certs); i++) {
        WOLFSSL_X509* x509 = wolfSSL_sk_X509_value(certs, i);
        if ((x509 != NULL) &&
                (wolfSSL_X509_NAME_cmp(&x509->subject, name) == 0)) {
            return x509;
        }
    }
    return NULL;
}

/* Looks up a cert in the store by subject name. CRLs are not looked up.
 * Returns 1 and puts a reference in obj when found, 0 otherwise. */
int wolfSSL_X509_STORE_CTX_get_by_subject(WOLFSSL_X509_STORE_CTX* ctx,
    WOLFSSL_X509_LOOKUP_TYPE type, WOLFSSL_X509_NAME* name,
    WOLFSSL_X509_OBJECT* obj)
{
    WOLFSSL_X509* x509;
#if defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM)
    WOLF_STACK_OF(WOLFSSL_X509)* sk;
#endif

    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_get_by_subject");

    if ((ctx == NULL) || (ctx->store == NULL) || (name == NULL) ||
            (obj == NULL) || (type != WOLFSSL_X509_LU_X509)) {
        return 0;
    }

    x509 = X509StoreFindBySubject(ctx->store->trusted, name);
    if (x509 == NULL) {
        x509 = X509StoreFindBySubject(ctx->store->certs, name);
    }
    if ((x509 != NULL) && (wolfSSL_X509_up_ref(x509) != WOLFSSL_SUCCESS)) {
        return 0;
    }
#if defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM)
    /* CAs loaded into the cert manager from files. */
    if (x509 == NULL) {
        sk = wolfSSL_X509_STORE_get1_certs(ctx, name);
        x509 = wolfSSL_sk_X509_value(sk, 0);
        if ((x509 != NULL) && (wolfSSL_X509_up_ref(x509) != WOLFSSL_SUCCESS)) {
            x509 = NULL;
        }
        wolfSSL_sk_X509_pop_free(sk, NULL);
    }
#endif
    if (x509 == NULL) {
        return 0;
    }

    obj->type = WOLFSSL_X509_LU_X509;
    obj->data.x509 = x509;
    return 1;
}

int wolfSSL_X509_STORE_get_by_subject(WOLFSSL_X509_STORE_CTX* ctx, int type,
                            WOLFSSL_X509_NAME* name, WOLFSSL_X509_OBJECT* obj)
{
    return wolfSSL_X509_STORE_CTX_get_by_subject(ctx,
        (WOLFSSL_X509_LOOKUP_TYPE)type, name, obj);
}

WOLFSSL_X509_VERIFY_PARAM *wolfSSL_X509_STORE_CTX_get0_param(
        WOLFSSL_X509_STORE_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->param;
}

/* Replace the param of ctx, including the values inherited from the store.
 * ctx takes ownership of param. A NULL param or the current one keeps the
 * current one. */
void wolfSSL_X509_STORE_CTX_set0_param(WOLFSSL_X509_STORE_CTX *ctx,
        WOLFSSL_X509_VERIFY_PARAM *param)
{
    WOLFSSL_ENTER("wolfSSL_X509_STORE_CTX_set0_param");
    if (ctx != NULL && param != NULL && param != ctx->param) {
        wolfSSL_X509_VERIFY_PARAM_free(ctx->param);
        ctx->param = param;
    }
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
    int i;
    int j;

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
        if (sk == NULL && wolfSSL_sk_X509_num(store->trusted) <= 0) {
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
                        filteredCert = NULL;
                        break;
                    }
                }
            }
            certToFilter = certToFilter->next;
        }
    }

    /* A trusted cert out of date when added is not in the cert manager */
    for (i = 0; err == 0 && i < wolfSSL_sk_X509_num(store->trusted); i++) {
        filteredCert = wolfSSL_sk_X509_value(store->trusted, i);
        if (wolfSSL_X509_NAME_cmp(&filteredCert->subject, name) != 0)
            continue;
        for (j = 0; j < wolfSSL_sk_X509_num(filteredCerts); j++) {
            if (X509DerEquals(wolfSSL_sk_X509_value(filteredCerts, j),
                    filteredCert))
                break;
        }
        if (j < wolfSSL_sk_X509_num(filteredCerts))
            continue;
        if (wolfSSL_X509_up_ref(filteredCert) != WOLFSSL_SUCCESS) {
            err = 1;
        }
        else if (wolfSSL_sk_X509_push(filteredCerts, filteredCert) <= 0) {
            wolfSSL_X509_free(filteredCert);
            err = 1;
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
    if (ret == WOLFSSL_SUCCESS) {
        return ret;
    }
#endif
    /* A trusted cert out of date when added is not in the cert manager */
    ret = X509StoreGetIssuerEx(issuer, ctx->store->trusted, x);
    if ((ret == WOLFSSL_SUCCESS) && (*issuer != NULL)) {
        return wolfSSL_X509_up_ref(*issuer);
    }

    return ret;
}
#endif /* WOLFSSL_NGINX || WOLFSSL_HAPROXY || OPENSSL_EXTRA || OPENSSL_ALL */

#ifdef OPENSSL_EXTRA

/* Returns 1 if the public key of ca verifies the signature of x, else 0.
 * An internal error is kept in *err. */
static int X509StoreKeySigned(WOLFSSL_X509* ca, WOLFSSL_X509* x, int* err)
{
    int ret;

    if (ca->pubKey.buffer == NULL || x->derCert == NULL) {
        return 0;
    }
    ret = CheckCertSignaturePubKey(x->derCert->buffer, x->derCert->length,
        x->heap, ca->pubKey.buffer, ca->pubKey.length, (int)ca->pubKeyOID);
    if (!X509StoreVerifyResult(ret)) {
        (void)X509StoreKeepErr(err, ret);
    }
    return ret == 0;
}

/* Returns 1 if ca may issue x, as in OpenSSL's check_issued(): the names
 * and key ids match and the key type of ca fits the signature of x. */
static int X509StoreIssued(WOLFSSL_X509* ca, WOLFSSL_X509* x)
{
    return wolfSSL_X509_check_issued(ca, x) == WOLFSSL_X509_V_OK &&
        SigOidMatchesKeyOid((word32)x->sigOID, (word32)ca->pubKeyOID);
}

static int X509StoreGetIssuerEx(WOLFSSL_X509 **issuer,
                            WOLFSSL_STACK * certs, WOLFSSL_X509 *x)
{
    int i;

    if (issuer == NULL || x == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (certs != NULL) {
        for (i = 0; i < wolfSSL_sk_X509_num(certs); i++) {
            WOLFSSL_X509* cand = wolfSSL_sk_X509_value(certs, i);

            if (X509StoreIssued(cand, x)) {
                *issuer = cand;
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

    if ((store->added = wolfSSL_sk_X509_new_null()) == NULL)
        goto err_exit;
#endif

#ifdef HAVE_CRL
    store->crl = store->cm->crl;
#endif

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)

    /* Link store's new Certificate Manager to self by default */
    store->cm->x509_store_p = store;

    if ((store->param = (WOLFSSL_X509_VERIFY_PARAM*)XMALLOC(
                           sizeof(WOLFSSL_X509_VERIFY_PARAM),
                           NULL, DYNAMIC_TYPE_OPENSSL)) == NULL) {
        goto err_exit;
    }
    XMEMSET(store->param, 0, sizeof(WOLFSSL_X509_VERIFY_PARAM));
    store->param->depth = -1;
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
                /* The manager may point back at this store, and can outlive
                 * it when something else holds a reference to it. Break the
                 * link before the store goes away so nothing is left
                 * pointing at freed memory. The back-pointer is only a field
                 * of the manager in the builds that can set it. */
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
                if (store->cm->x509_store_p == store) {
                    store->cm->x509_store_p = NULL;
                }
#endif
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
            wolfSSL_sk_X509_free(store->added);
            store->added = NULL;
#endif
#ifdef OPENSSL_ALL
            if (store->objs != NULL) {
                wolfSSL_sk_X509_OBJECT_pop_free(store->objs, NULL);
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

/* Take a reference to a certificate store.
 *
 * Only a store allocated by wolfSSL_X509_STORE_new() is reference counted. A
 * store that is part of another object - the one a context returns from
 * wolfSSL_CTX_get_cert_store() when none has been set on it, for example -
 * has no count to take, and its lifetime is that of the object holding it.
 * Success is still reported for such a store, so unlike OpenSSL's
 * X509_STORE_up_ref() a successful return does not by itself mean the caller
 * now owns something that keeps the store alive. A caller that intends to
 * outlive the object the store belongs to cannot rely on this call and must
 * use a store of its own.
 *
 * @param [in, out] store  Certificate store.
 * @return  1 on success, including for a store that has no reference count.
 * @return  0 when store is NULL, or when the count could not be taken.
 */
int wolfSSL_X509_STORE_up_ref(WOLFSSL_X509_STORE* store)
{
    if (store == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* A store that is part of another object, such as the one in a context,
     * is not reference counted - its reference count was never initialized
     * and its lifetime is that of the object holding it. Nothing to do, as
     * in wolfSSL_X509_STORE_free(). */
    if (store->isDynamic) {
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
    }

    return WOLFSSL_SUCCESS;
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
    int verify = VERIFY;

    WOLFSSL_ENTER("X509StoreAddCa");
    if (store != NULL && x509 != NULL && x509->derCert != NULL) {
        /* Check if NO_CHECK_TIME flag is set - if so, skip date validation.
         * A store of its own keeps a CA out of date out of the cert manager
         * also with the flag: TLS would trust it for good. */
        if (store->trusted == NULL && store->param != NULL &&
            (store->param->flags & WOLFSSL_NO_CHECK_TIME) != 0) {
            verify = VERIFY_SKIP_DATE;
        }
        result = AllocDer(&derCert, x509->derCert->length,
            x509->derCert->type, NULL);
        if (result == 0) {
            /* AddCA() frees the buffer. */
            XMEMCPY(derCert->buffer,
                            x509->derCert->buffer, x509->derCert->length);
            result = AddCA(store->cm, &derCert, type, verify);
        }
    }

    return result;
}

/* Push certificates from the store's X509 stacks (certs and trusted) into the
 * CertManager, then free and NULL the stacks to signal that this store is now
 * owned by an SSL_CTX.
 *
 * This is needed when an X509_STORE is attached to an SSL_CTX via
 * SSL_CTX_set_cert_store: self-signed CAs are already in the CM (added by
 * X509StoreAddCa during X509_STORE_add_cert), but non-self-signed intermediates
 * are only in store->certs and must be explicitly added to the CM so that all
 * verification paths (including CertManagerVerify) can find them. */
WOLFSSL_LOCAL int X509StorePushCertsToCM(WOLFSSL_X509_STORE* store)
{
    int i;
    int num;
    int ret;
    int anyFail = 0;
    WOLFSSL_X509* x509;

    WOLFSSL_ENTER("X509StorePushCertsToCM");

    if (store == NULL || store->cm == NULL)
        return WOLFSSL_SUCCESS;

    /* Push trusted certs first, while the store is not yet the store of an
     * SSL_CTX: their dates are checked. Self-signed CAs are typically already
     * in the CM (added during X509_STORE_add_cert), but AddCA handles
     * duplicates. */
    if (store->trusted != NULL) {
        num = wolfSSL_sk_X509_num(store->trusted);
        for (i = 0; i < num; i++) {
            x509 = wolfSSL_sk_X509_value(store->trusted, i);
            if (x509 != NULL) {
                ret = X509StoreAddCa(store, x509, WOLFSSL_USER_CA);
                /* A cert out of date stays out of the CM and is dropped */
                if (ret != WOLFSSL_SUCCESS &&
                        ret != WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E) &&
                        ret != WC_NO_ERR_TRACE(ASN_AFTER_DATE_E)) {
                    WOLFSSL_MSG("X509StorePushCertsToCM: failed to add "
                                "trusted cert");
                    anyFail = 1;
                }
            }
        }
        wolfSSL_sk_X509_pop_free(store->trusted, NULL);
        store->trusted = NULL;
    }

    /* Push non-self-signed intermediates from store->certs into the CM. */
    if (store->certs != NULL) {
        num = wolfSSL_sk_X509_num(store->certs);
        for (i = 0; i < num; i++) {
            x509 = wolfSSL_sk_X509_value(store->certs, i);
            if (x509 != NULL) {
                ret = X509StoreAddCa(store, x509, WOLFSSL_USER_CA);
                if (ret != WOLFSSL_SUCCESS) {
                    WOLFSSL_MSG("X509StorePushCertsToCM: failed to add cert");
                    anyFail = 1;
                }
            }
        }
        /* Free and NULL to mark store as CTX-owned. Future add_cert calls
         * will go directly to the CertManager. */
        wolfSSL_sk_X509_pop_free(store->certs, NULL);
        store->certs = NULL;
    }
    wolfSSL_sk_X509_free(store->added);
    store->added = NULL;

    if (anyFail) {
        return WOLFSSL_FATAL_ERROR;
    }
    return WOLFSSL_SUCCESS;
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
            /* As OpenSSL, a store of its own takes a cert out of date now.
             * It stays out of the cert manager, so TLS does not trust it.
             * X509_verify_cert() checks its dates at the verification time. */
            if (store->trusted != NULL &&
                    (result == WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E) ||
                     result == WC_NO_ERR_TRACE(ASN_AFTER_DATE_E))) {
                result = WOLFSSL_SUCCESS;
            }
            /* As OpenSSL, adding a cert already there is a no-op */
            if (result == WOLFSSL_SUCCESS && store->trusted != NULL &&
                    !X509StoreCertIsTrusted(store, x509, NULL)) {
                result = wolfSSL_X509_up_ref(x509);
                if (result == WOLFSSL_SUCCESS) {
                    result = wolfSSL_sk_X509_push(store->trusted, x509);
                    if (result > 0) {
                        /* OpenSSL picks among certs of a name in the order
                         * they were added. */
                        result = (wolfSSL_sk_X509_push(store->added, x509) > 0)
                            ? WOLFSSL_SUCCESS : WOLFSSL_FATAL_ERROR;
                    }
                    else {
                        result = WOLFSSL_FATAL_ERROR;
                        wolfSSL_X509_free(x509);
                        x509 = NULL;
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
                        result = (wolfSSL_sk_X509_push(store->added, x509) > 0)
                            ? WOLFSSL_SUCCESS : WOLFSSL_FATAL_ERROR;
                    }
                    else {
                        result = WOLFSSL_FATAL_ERROR;
                        wolfSSL_X509_free(x509);
                        x509 = NULL;
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
    int crlOpts = 0;

    WOLFSSL_ENTER("wolfSSL_X509_STORE_set_flags");

    if (store == NULL)
        return WOLFSSL_FAILURE;

    /* X509_V_FLAG_CRL_CHECK(_ALL), and the native WOLFSSL_CRL_CHECK(ALL)
     * options for compatibility. */
    if (flag & (WOLFSSL_X509_V_FLAG_CRL_CHECK | WOLFSSL_CRL_CHECK)) {
        crlOpts |= WOLFSSL_CRL_CHECK;
    }
    if (flag & (WOLFSSL_X509_V_FLAG_CRL_CHECK_ALL | WOLFSSL_CRL_CHECKALL)) {
        crlOpts |= WOLFSSL_CRL_CHECKALL;
    }

    if (crlOpts != 0) {
        ret = wolfSSL_CertManagerEnableCRL(store->cm, crlOpts);
    }
#if defined(OPENSSL_COMPATIBLE_DEFAULTS)
    else if (flag == 0) {
        ret = wolfSSL_CertManagerDisableCRL(store->cm);
    }
#endif
    if (flag & WOLFSSL_PARTIAL_CHAIN) {
        store->param->flags |= WOLFSSL_PARTIAL_CHAIN;
    }
    if (flag & WOLFSSL_X509_STRICT) {
        store->param->flags |= WOLFSSL_X509_STRICT;
    }
    /* As OpenSSL, also without HAVE_CRL. Not X509_V_FLAG_NO_CHECK_TIME: on
     * the store of an SSL_CTX it lets CAs out of date into the cert
     * manager. */
    store->param->flags |= flag & (WOLFSSL_X509_V_FLAG_CRL_CHECK |
        WOLFSSL_X509_V_FLAG_CRL_CHECK_ALL);
    return ret;
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
    if (x509 != NULL) {
        ret = wolfSSL_X509_STORE_add_cert(str, x509);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Failed to load file");
            ret = WOLFSSL_FAILURE;
        }
        if (ret == WOLFSSL_SUCCESS && str->owned != NULL) {
            if (wolfSSL_sk_X509_push(str->owned, x509) <= 0) {
                ret = WOLFSSL_FAILURE;
            }
            else {
                x509 = NULL;
            }
        }
        wolfSSL_X509_free(x509);
        x509 = NULL;
    }
    else {
        ret = WOLFSSL_FAILURE;
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
                (XSTRNSTR((char*)content->buffer, header, sz) !=
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

    WOLFSSL_MSG_EX("X509StoreLoadFile: Loading file: %s", fname);

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
int wolfSSL_X509_STORE_load_locations(WOLFSSL_X509_STORE *str,
                                            const char *file, const char *dir)
{
    WOLFSSL_CTX* ctx;
    char *name = NULL;
    int ret = WOLFSSL_SUCCESS;
    WC_DECLARE_VAR(readCtx, ReadDirCtx, 1, 0);

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

            WC_FREE_VAR_EX(readCtx, ctx->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    ctx->cm = NULL;
    wolfSSL_CTX_free(ctx);

    return ret;
}

#if defined(XGETENV) && !defined(NO_GETENV)
int wolfSSL_X509_STORE_set_default_paths(WOLFSSL_X509_STORE *str)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    char* certDir = NULL;
    char* certFile = NULL;

    WOLFSSL_ENTER("wolfSSL_X509_STORE_set_default_paths");

    if (str == NULL)
        return WOLFSSL_FAILURE;

    certFile = wc_strdup_ex(XGETENV("SSL_CERT_FILE"), DYNAMIC_TYPE_TMP_BUFFER);
    certDir = wc_strdup_ex(XGETENV("SSL_CERT_DIR"), DYNAMIC_TYPE_TMP_BUFFER);

    /* As OpenSSL: the default locations are optional. There is no built-in
     * bundle, and one that does not load is not an error. */
    ret = WOLFSSL_SUCCESS;
    if ((certFile != NULL || certDir != NULL) &&
            wolfSSL_X509_STORE_load_locations(str, certFile, certDir) !=
            WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Default locations not loaded");
        wolfSSL_ERR_clear_error();
    }

    XFREE(certFile, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(certDir, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif /* XGETENV && !NO_GETENV */

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
                x509 = NULL;
                goto error;
            }
        }
        else {
            wolfSSL_X509_free(x509);
            x509 = NULL;
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
    int j;
    int n;
#endif
    WOLFSSL_ENTER("wolfSSL_X509_STORE_get0_objects");

    if (store == NULL || store->cm == NULL) {
        WOLFSSL_MSG("Missing or empty store");
        return NULL;
    }

    if (store->objs != NULL) {
#if defined(WOLFSSL_SIGNER_DER_CERT) && !defined(NO_FILESYSTEM)
        /* want to update objs stack by cm stack again before returning it*/
        wolfSSL_sk_X509_OBJECT_pop_free(store->objs, NULL);
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
    if (cert_stack == NULL && (wolfSSL_sk_X509_num(store->certs) > 0 ||
            wolfSSL_sk_X509_num(store->trusted) > 0)) {
        cert_stack = wolfSSL_sk_X509_new_null();
        if (cert_stack == NULL) {
            WOLFSSL_MSG("wolfSSL_sk_X509_OBJECT_new error");
            goto err_cleanup;
        }
    }
    /* Reference borrowed certs so cert_stack owns every entry. */
    for (i = 0; i < wolfSSL_sk_X509_num(store->certs); i++) {
        x509 = wolfSSL_sk_X509_value(store->certs, i);
        if (wolfSSL_X509_up_ref(x509) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_X509_up_ref error");
            goto err_cleanup;
        }
        if (wolfSSL_sk_X509_push(cert_stack, x509) <= 0) {
            WOLFSSL_MSG("wolfSSL_sk_X509_push error");
            wolfSSL_X509_free(x509);
            goto err_cleanup;
        }
    }
    /* A trusted cert out of date when added is not in the cert manager */
    n = wolfSSL_sk_X509_num(cert_stack);
    for (i = 0; i < wolfSSL_sk_X509_num(store->trusted); i++) {
        x509 = wolfSSL_sk_X509_value(store->trusted, i);
        for (j = 0; j < n; j++) {
            if (X509DerEquals(wolfSSL_sk_X509_value(cert_stack, j), x509))
                break;
        }
        if (j < n)
            continue;
        if (wolfSSL_X509_up_ref(x509) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_X509_up_ref error");
            goto err_cleanup;
        }
        if (wolfSSL_sk_X509_push(cert_stack, x509) <= 0) {
            WOLFSSL_MSG("wolfSSL_sk_X509_push error");
            wolfSSL_X509_free(x509);
            goto err_cleanup;
        }
    }
    for (i = 0; i < wolfSSL_sk_X509_num(cert_stack); i++) {
        x509 = (WOLFSSL_X509 *)wolfSSL_sk_value(cert_stack, i);
        obj  = wolfSSL_X509_OBJECT_new();
        if (obj == NULL) {
            WOLFSSL_MSG("wolfSSL_X509_OBJECT_new error");
            goto err_cleanup;
        }
        /* Push first so cleanup frees the object if the up_ref fails. */
        if (wolfSSL_sk_X509_OBJECT_push(ret, obj) <= 0) {
            WOLFSSL_MSG("wolfSSL_sk_X509_OBJECT_push error");
            wolfSSL_X509_OBJECT_free(obj);
            goto err_cleanup;
        }
        /* Object owns a reference, so the list frees independently. */
        if (wolfSSL_X509_up_ref(x509) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_X509_up_ref error");
            goto err_cleanup;
        }
        obj->type = WOLFSSL_X509_LU_X509;
        obj->data.x509 = x509;
    }
#endif

#ifdef HAVE_CRL
    if (store->cm->crl != NULL) {
        int res;
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
        /* Reference first, so the object only claims what it can free. */
        wolfSSL_RefInc(&store->cm->crl->ref, &res);
        if (res != 0) {
            WOLFSSL_MSG("Failed to lock crl mutex");
            goto err_cleanup;
        }
        obj->type = WOLFSSL_X509_LU_CRL;
        obj->data.crl = store->cm->crl;
    }
#endif

    if (cert_stack != NULL)
        wolfSSL_sk_X509_pop_free(cert_stack, NULL);
    store->objs = ret;
    return ret;
err_cleanup:
    /* Objects own their contents, so one pop_free releases everything. */
    if (ret != NULL)
        wolfSSL_sk_X509_OBJECT_pop_free(ret, NULL);
    if (cert_stack != NULL)
        wolfSSL_sk_X509_pop_free(cert_stack, NULL);
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
