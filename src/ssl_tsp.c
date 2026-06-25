/* ssl_tsp.c
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

#include <wolfssl/internal.h>

#if !defined(WOLFSSL_SSL_TSP_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_tsp.c does not need to be compiled separately from ssl.c
    #endif
#else

#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && \
    defined(WOLFSSL_TSP_VERIFIER)

/* The TSP OpenSSL compat layer uses the OpenSSL ASN.1 helpers (e.g.
 * wolfssl_asn1_integer_new_buf) from ssl_asn1.c, which is omitted when
 * OPENSSL_EXTRA_NO_ASN1 is defined. */
#ifdef OPENSSL_EXTRA_NO_ASN1
#error "TSP OpenSSL compat layer requires the OpenSSL ASN.1 API \
(OPENSSL_EXTRA_NO_ASN1 not supported with WOLFSSL_TSP)"
#endif

#include <wolfssl/openssl/ts.h>
#include <wolfssl/openssl/pkcs7.h>
#include <wolfssl/wolfcrypt/tsp.h>

/* Time-Stamp Protocol (RFC 3161) compatibility layer.
 *
 * Implements both sides with the wc_Tsp API: the requester (create and encode
 * requests, decode and verify responses) and, under WOLFSSL_TSP_RESPONDER, the
 * responder (TS_RESP_CTX, decode requests, create responses). The whole layer
 * is gated on WOLFSSL_TSP_VERIFIER, so a responder-only build without the
 * verifier exposes no OpenSSL TS API.
 *
 * The wolfCrypt Tsp data structure (TspRequest, TspTstInfo, TspResponse) is
 * embedded in the compatibility object and is the single source of truth.
 * Loading and storing - including d2i and i2d - go through the wc_Tsp API
 * and operate on the embedded structure directly.
 *
 * OpenSSL-style sub-objects (ASN1_INTEGER, ASN1_OBJECT, ...) are not stored.
 * A getter that returns one creates it from the wc data on first use, caches
 * it on the parent and frees it when the parent is freed - the returned
 * pointer is valid for the life of the parent and must not be freed by the
 * caller. A setter copies the supplied object's value into the wc data and
 * discards any cached view so it is rebuilt on the next get.
 */

/* MessageImprint - hash algorithm and hash of the data being time-stamped.
 * RFC 3161, 2.4.1. A field of TS_REQ and TS_TST_INFO, and a standalone object
 * (TS_MSG_IMPRINT_new). */
struct WOLFSSL_TS_MSG_IMPRINT {
    /* Source of truth. Points to miStore when standalone, or to the imprint
     * embedded in the parent (TS_REQ/TS_TST_INFO) when a field of one. */
    TspMessageImprint* mi;
    /* Imprint storage used only when the object is standalone. */
    TspMessageImprint miStore;
    /* Hash algorithm view (X509_ALGOR) - owned, built from mi on first get. */
    WOLFSSL_X509_ALGOR* algo;
    /* Hashed message view (OCTET STRING) - owned, built from mi on first
     * get; its data references mi's hash. */
    WOLFSSL_ASN1_STRING* msg;
};

/* TimeStampReq - the request sent to a TSA. RFC 3161, 2.4.1.
 * Writable: built with the setters then encoded, or decoded from DER. */
struct WOLFSSL_TS_REQ {
    /* Source of truth - fully owns its data (no references into a buffer). */
    TspRequest req;
    /* Message imprint view - owned, built from req.imprint on first get. */
    WOLFSSL_TS_MSG_IMPRINT* msgImprint;
    /* Policy OID view - owned, built from req.policy on first get. */
    WOLFSSL_ASN1_OBJECT* policy;
    /* Nonce view (INTEGER) - owned, built from req.nonce on first get. */
    WOLFSSL_ASN1_INTEGER* nonce;
};

/* Accuracy - bound on the error of the time in a TSTInfo. RFC 3161, 2.4.2.
 * A read-only view returned by TS_TST_INFO_get_accuracy(). */
struct WOLFSSL_TS_ACCURACY {
    /* References the accuracy embedded in the parent TS_TST_INFO. */
    const TspAccuracy* acc;
    /* Part views (INTEGER) - owned, built from acc on first get. A part that
     * is zero is treated as absent and its getter returns NULL. */
    WOLFSSL_ASN1_INTEGER* seconds;
    WOLFSSL_ASN1_INTEGER* millis;
    WOLFSSL_ASN1_INTEGER* micros;
};

/* PKIStatusInfo - status of a time-stamp response. RFC 3161, 2.4.2.
 * A read-only view returned by TS_RESP_get_status_info(). */
struct WOLFSSL_TS_STATUS_INFO {
    /* References the response embedded in the parent TS_RESP. */
    const TspResponse* resp;
    /* PKIStatus view (INTEGER) - owned, built from resp on first get. */
    WOLFSSL_ASN1_INTEGER* status;
    /* PKIFailureInfo view (BIT STRING) - owned, built on first get; NULL when
     * no failure information is present. */
    WOLFSSL_ASN1_BIT_STRING* failInfo;
    /* PKIFreeText view - a stack holding only the first UTF8String (all the
     * wc layer exposes). Owned; textStr references the string in resp's der. */
    WOLFSSL_STACK* text;
    WOLFSSL_ASN1_STRING* textStr;
};

/* TSTInfo - the time-stamp token content signed by the TSA. RFC 3161, 2.4.2.
 * Read-only: decoded from DER (or extracted from a token); i2d re-emits der. */
struct WOLFSSL_TS_TST_INFO {
    /* The DER encoding - owned. The wc TSTInfo references into it. */
    unsigned char* der;
    word32 derSz;
    /* Source of truth - decoded from der and references into it. */
    TspTstInfo tst;
    /* Policy OID view - owned, built from tst.policy on first get. */
    WOLFSSL_ASN1_OBJECT* policy;
    /* Message imprint view - owned, built from tst.imprint on first get. */
    WOLFSSL_TS_MSG_IMPRINT* msgImprint;
    /* Serial number view (INTEGER) - owned, built from tst on first get. */
    WOLFSSL_ASN1_INTEGER* serial;
    /* Time view (GeneralizedTime) - owned, built from tst on first get. */
    WOLFSSL_ASN1_TIME* time;
    /* Accuracy view - owned, built on first get; NULL when not present. */
    WOLFSSL_TS_ACCURACY* accuracy;
    /* Nonce view (INTEGER) - owned, built on first get; NULL when absent. */
    WOLFSSL_ASN1_INTEGER* nonce;
    /* TSA name view (GeneralName) - owned, built on first get; NULL when
     * absent. */
    WOLFSSL_GENERAL_NAME* tsa;
};

/* TimeStampResp - the response returned by a TSA. RFC 3161, 2.4.2.
 * Read-only: decoded from DER; i2d re-emits der. */
struct WOLFSSL_TS_RESP {
    /* The DER encoding - owned. The wc response references into it. */
    unsigned char* der;
    word32 derSz;
    /* Source of truth - decoded from der and references into it. */
    TspResponse resp;
    /* Status info view - owned, built on first get. */
    WOLFSSL_TS_STATUS_INFO* statusInfo;
    /* TSTInfo of the token - owned, created on first get by verifying the
     * token and decoding its content; NULL when there is no valid token. */
    WOLFSSL_TS_TST_INFO* tstInfo;
};

/* Verification context - expected values and checks for verifying a response
 * or token. The OpenSSL TS_VERIFY_CTX; has no wc counterpart. */
struct WOLFSSL_TS_VERIFY_CTX {
    /* TS_VFY_* flags selecting which checks to perform. */
    unsigned int flags;
    /* Trusted certificate store for the signer check - owned. May be NULL. */
    WOLFSSL_X509_STORE* store;
    /* Expected message imprint hash - owned. */
    unsigned char* imprint;
    word32 imprintSz;
    /* Expected nonce as the wc value bytes. Absent when nonceSz is 0. */
    unsigned char nonce[MAX_TS_NONCE_SZ];
    word32 nonceSz;
    /* Expected policy as the OID content bytes. Absent when policySz is 0. */
    unsigned char policy[MAX_OID_SZ];
    word32 policySz;
    /* Data to hash and check against the imprint for TS_VFY_DATA - owned,
     * freed on cleanup like OpenSSL. NULL when not set. */
    WOLFSSL_BIO* data;
};

/******************************************************************************
 * Field helpers
 *****************************************************************************/

#if defined(WOLFSSL_TSP_REQUESTER) || defined(WOLFSSL_TSP_RESPONDER)
/* Get the number data and length out of an ASN1_INTEGER.
 *
 * Used for the unsigned big-endian numbers of TSP: a request's nonce
 * (requester) and a response's serial number (responder).
 *
 * @param [in]  a     ASN1_INTEGER object.
 * @param [out] data  Big-endian encoding of number.
 * @param [out] len   Length of number in bytes.
 * @return  1 on success.
 * @return  0 on failure or when the number is negative.
 */
static int ts_asn1_integer_get(const WOLFSSL_ASN1_INTEGER* a,
    const unsigned char** data, word32* len)
{
    word32 idx = 1;
    int length = 0;

    if ((a == NULL) || (a->length < 3) || (a->data[0] != ASN_INTEGER))
        return 0;
    /* The number is an unsigned big-endian value. The data holds the
     * magnitude; the sign is carried separately - reject a negative value
     * rather than use its magnitude as if positive. */
    if (a->negative || (a->type == WOLFSSL_V_ASN1_NEG_INTEGER))
        return 0;
    if (GetLength(a->data, &idx, &length, (word32)a->length) < 0)
        return 0;

    *data = a->data + idx;
    *len = (word32)length;
    return 1;
}
#endif /* WOLFSSL_TSP_REQUESTER || WOLFSSL_TSP_RESPONDER */

/* Return the encoding in the i2d output parameter style.
 *
 * @param [in]      der    DER encoding.
 * @param [in]      derSz  Length of encoding in bytes.
 * @param [in, out] pp     Output buffer pointer. May be NULL. When pointer
 *                         to NULL, a buffer is allocated and not advanced.
 *                         Otherwise written to and advanced.
 * @return  Length of encoding on success.
 * @return  -1 on failure.
 */
static int ts_i2d(const unsigned char* der, word32 derSz, unsigned char** pp)
{
    if (der == NULL)
        return -1;
    if (pp == NULL)
        return (int)derSz;

    if (*pp == NULL) {
        *pp = (unsigned char*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_OPENSSL);
        if (*pp == NULL)
            return -1;
        XMEMCPY(*pp, der, derSz);
    }
    else {
        XMEMCPY(*pp, der, derSz);
        *pp += derSz;
    }
    return (int)derSz;
}

/* Get the length of the complete ASN.1 item at the front of the buffer.
 *
 * @param [in] der  Buffer holding DER encoding.
 * @param [in] len  Length of data in buffer in bytes.
 * @return  Length of ASN.1 item on success.
 * @return  0 on failure.
 */
static word32 ts_msg_len(const unsigned char* der, long len)
{
    word32 idx = 0;
    int length = 0;

    if ((der == NULL) || (len <= 0))
        return 0;
    /* Outer item is a SEQUENCE - return the total length of the item. */
    if (GetSequence(der, &idx, &length, (word32)len) < 0)
        return 0;
    return idx + (word32)length;
}

/* Create an ASN1_INTEGER holding a small number.
 *
 * @param [in] v  Value of number.
 * @return  ASN1_INTEGER object on success.
 * @return  NULL on failure.
 */
static WOLFSSL_ASN1_INTEGER* ts_asn1_integer_new_num(long v)
{
    WOLFSSL_ASN1_INTEGER* a = wolfSSL_ASN1_INTEGER_new();
    if ((a != NULL) && (wolfSSL_ASN1_INTEGER_set(a, v) != 1)) {
        wolfSSL_ASN1_INTEGER_free(a);
        a = NULL;
    }
    return a;
}

/******************************************************************************
 * TS_MSG_IMPRINT
 *****************************************************************************/

/* Create a message imprint object that views an imprint.
 *
 * @param [in] mi  Imprint to view. When NULL the object's own storage is
 *                 used.
 * @return  Message imprint object on success.
 * @return  NULL on failure.
 */
static WOLFSSL_TS_MSG_IMPRINT* ts_msg_imprint_new(TspMessageImprint* mi)
{
    WOLFSSL_TS_MSG_IMPRINT* a;

    a = (WOLFSSL_TS_MSG_IMPRINT*)XMALLOC(sizeof(WOLFSSL_TS_MSG_IMPRINT),
        NULL, DYNAMIC_TYPE_OPENSSL);
    if (a != NULL) {
        XMEMSET(a, 0, sizeof(WOLFSSL_TS_MSG_IMPRINT));
        a->mi = (mi != NULL) ? mi : &a->miStore;
    }

    return a;
}

/* Create a new message imprint.
 *
 * @return  Message imprint object on success.
 * @return  NULL on failure.
 */
WOLFSSL_TS_MSG_IMPRINT* wolfSSL_TS_MSG_IMPRINT_new(void)
{
    return ts_msg_imprint_new(NULL);
}

/* Dispose of a message imprint.
 *
 * @param [in, out] a  Message imprint object. May be NULL.
 */
void wolfSSL_TS_MSG_IMPRINT_free(WOLFSSL_TS_MSG_IMPRINT* a)
{
    if (a != NULL) {
        if (a->algo != NULL)
            wolfSSL_X509_ALGOR_free(a->algo);
        if (a->msg != NULL)
            wolfSSL_ASN1_STRING_free(a->msg);
        XFREE(a, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

/* Set the hash algorithm of a message imprint.
 *
 * The algorithm is copied as its OID sum.
 *
 * @param [in, out] a    Message imprint object.
 * @param [in]      alg  Hash algorithm.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_TS_MSG_IMPRINT_set_algo(WOLFSSL_TS_MSG_IMPRINT* a,
    WOLFSSL_X509_ALGOR* alg)
{
    int nid;
    word32 oidSum;

    if ((a == NULL) || (alg == NULL) || (alg->algorithm == NULL))
        return 0;
    /* No work when setting the algorithm onto itself. */
    if (alg == a->algo)
        return 1;

    /* Convert the algorithm to a hash OID sum for the wc imprint.
     * nid2oid returns (word32)-1 when the NID is not a known hash. */
    nid = wolfSSL_OBJ_obj2nid(alg->algorithm);
    oidSum = (word32)nid2oid(nid, oidHashType);
    if ((oidSum == 0) || (oidSum == (word32)-1))
        return 0;
    a->mi->hashAlgOID = oidSum;

    /* Discard any cached view so it is rebuilt from the wc imprint. */
    if (a->algo != NULL) {
        wolfSSL_X509_ALGOR_free(a->algo);
        a->algo = NULL;
    }

    return 1;
}

/* Get the hash algorithm of a message imprint.
 *
 * @param [in] a  Message imprint object.
 * @return  Hash algorithm of the object - do not free.
 * @return  NULL when a is NULL.
 */
WOLFSSL_X509_ALGOR* wolfSSL_TS_MSG_IMPRINT_get_algo(WOLFSSL_TS_MSG_IMPRINT* a)
{
    WOLFSSL_X509_ALGOR* alg;

    if (a == NULL)
        return NULL;

    if (a->algo != NULL)
        return a->algo;

    alg = wolfSSL_X509_ALGOR_new();
    if (alg == NULL)
        return NULL;
    /* Algorithm OBJECT IDENTIFIER from the wc imprint's OID sum. */
    alg->algorithm = wolfSSL_OBJ_nid2obj(oid2nid(a->mi->hashAlgOID,
        oidHashType));
    if (alg->algorithm == NULL) {
        wolfSSL_X509_ALGOR_free(alg);
        return NULL;
    }
    a->algo = alg;

    return a->algo;
}

/* Set the hashed message of a message imprint.
 *
 * @param [in, out] a    Message imprint object.
 * @param [in]      d    Hash of message.
 * @param [in]      len  Length of hash in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_TS_MSG_IMPRINT_set_msg(WOLFSSL_TS_MSG_IMPRINT* a,
    unsigned char* d, int len)
{
    if ((a == NULL) || (d == NULL) || (len <= 0) ||
            (len > WC_TSP_MAX_HASH_SZ))
        return 0;

    XMEMCPY(a->mi->hash, d, (size_t)len);
    a->mi->hashSz = (word32)len;

    /* Discard any cached view so it is rebuilt from the wc imprint. */
    if (a->msg != NULL) {
        wolfSSL_ASN1_STRING_free(a->msg);
        a->msg = NULL;
    }

    return 1;
}

/* Get the hashed message of a message imprint.
 *
 * @param [in] a  Message imprint object.
 * @return  Hashed message of the object - do not free.
 * @return  NULL when a is NULL.
 */
WOLFSSL_ASN1_STRING* wolfSSL_TS_MSG_IMPRINT_get_msg(WOLFSSL_TS_MSG_IMPRINT* a)
{
    if (a == NULL)
        return NULL;

    if (a->msg == NULL) {
        WOLFSSL_ASN1_STRING* s = wolfSSL_ASN1_STRING_new();
        if (s == NULL)
            return NULL;
        /* Reference the hash in the wc imprint. */
        s->data = (char*)a->mi->hash;
        s->length = (int)a->mi->hashSz;
        s->type = WOLFSSL_V_ASN1_OCTET_STRING;
        s->isDynamic = 0;
        a->msg = s;
    }

    return a->msg;
}

#ifdef WOLFSSL_TSP_REQUESTER
/******************************************************************************
 * TS_REQ
 *****************************************************************************/

/* Create a new time-stamp request.
 *
 * @return  TS_REQ object on success.
 * @return  NULL on failure.
 */
WOLFSSL_TS_REQ* wolfSSL_TS_REQ_new(void)
{
    WOLFSSL_TS_REQ* a;

    a = (WOLFSSL_TS_REQ*)XMALLOC(sizeof(WOLFSSL_TS_REQ), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (a != NULL) {
        XMEMSET(a, 0, sizeof(WOLFSSL_TS_REQ));
        if (wc_TspRequest_Init(&a->req) != 0) {
            XFREE(a, NULL, DYNAMIC_TYPE_OPENSSL);
            a = NULL;
        }
    }

    return a;
}

/* Dispose of a time-stamp request.
 *
 * @param [in, out] a  TS_REQ object. May be NULL.
 */
void wolfSSL_TS_REQ_free(WOLFSSL_TS_REQ* a)
{
    if (a != NULL) {
        wolfSSL_TS_MSG_IMPRINT_free(a->msgImprint);
        wolfSSL_ASN1_OBJECT_free(a->policy);
        wolfSSL_ASN1_INTEGER_free(a->nonce);
        XFREE(a, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

/* Set the version of a time-stamp request - must be 1.
 *
 * @param [in, out] a        TS_REQ object.
 * @param [in]      version  Version of request.
 * @return  1 on success.
 * @return  0 when a is NULL.
 */
int wolfSSL_TS_REQ_set_version(WOLFSSL_TS_REQ* a, long version)
{
    if (a == NULL)
        return 0;
    a->req.version = (byte)version;
    return 1;
}

/* Get the version of a time-stamp request.
 *
 * @param [in] a  TS_REQ object.
 * @return  Version of request.
 * @return  0 when a is NULL.
 */
long wolfSSL_TS_REQ_get_version(const WOLFSSL_TS_REQ* a)
{
    if (a == NULL)
        return 0;
    return (long)a->req.version;
}

/* Set the message imprint of a time-stamp request.
 *
 * The message imprint is copied.
 *
 * @param [in, out] a           TS_REQ object.
 * @param [in]      msgImprint  Message imprint object.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_TS_REQ_set_msg_imprint(WOLFSSL_TS_REQ* a,
    WOLFSSL_TS_MSG_IMPRINT* msgImprint)
{
    if ((a == NULL) || (msgImprint == NULL))
        return 0;
    /* No work when setting the message imprint onto itself. */
    if (msgImprint == a->msgImprint)
        return 1;

    /* Copy the imprint into the wc request. */
    XMEMCPY(&a->req.imprint, msgImprint->mi, sizeof(TspMessageImprint));

    /* Discard any cached view so it is rebuilt from the wc request. */
    wolfSSL_TS_MSG_IMPRINT_free(a->msgImprint);
    a->msgImprint = NULL;

    return 1;
}

/* Get the message imprint of a time-stamp request.
 *
 * @param [in] a  TS_REQ object.
 * @return  Message imprint of the object - do not free.
 * @return  NULL when a is NULL.
 */
WOLFSSL_TS_MSG_IMPRINT* wolfSSL_TS_REQ_get_msg_imprint(WOLFSSL_TS_REQ* a)
{
    if (a == NULL)
        return NULL;
    if (a->msgImprint == NULL)
        a->msgImprint = ts_msg_imprint_new(&a->req.imprint);
    return a->msgImprint;
}

/* Set the TSA policy of a time-stamp request.
 *
 * The policy is copied.
 *
 * @param [in, out] a       TS_REQ object.
 * @param [in]      policy  TSA policy ID.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_TS_REQ_set_policy_id(WOLFSSL_TS_REQ* a,
    const WOLFSSL_ASN1_OBJECT* policy)
{
    const unsigned char* oid;
    word32 oidSz;
    word32 idx = 1;
    int len = 0;

    if ((a == NULL) || (policy == NULL) || (policy->obj == NULL))
        return 0;

    /* The object's OID may be full DER (OBJECT IDENTIFIER tag, length then
     * content) or bare content - the wc request holds the content. */
    oid = policy->obj;
    oidSz = policy->objSz;
    if ((oidSz >= 2) && (oid[0] == ASN_OBJECT_ID) &&
            (GetLength(oid, &idx, &len, oidSz) >= 0) &&
            (idx + (word32)len == oidSz)) {
        oid += idx;
        oidSz = (word32)len;
    }
    if ((oidSz == 0) || (oidSz > MAX_OID_SZ))
        return 0;

    XMEMCPY(a->req.policy, oid, oidSz);
    a->req.policySz = oidSz;

    /* Discard any cached view so it is rebuilt from the wc request. */
    wolfSSL_ASN1_OBJECT_free(a->policy);
    a->policy = NULL;

    return 1;
}

/* Get the TSA policy of a time-stamp request.
 *
 * @param [in] a  TS_REQ object.
 * @return  TSA policy ID of the object - do not free.
 * @return  NULL when a is NULL or no policy set.
 */
WOLFSSL_ASN1_OBJECT* wolfSSL_TS_REQ_get_policy_id(WOLFSSL_TS_REQ* a)
{
    if ((a == NULL) || (a->req.policySz == 0))
        return NULL;
    /* Build the object from the OID content in the wc request. */
    if (a->policy == NULL) {
        const unsigned char* p = a->req.policy;
        a->policy = wolfSSL_c2i_ASN1_OBJECT(NULL, &p, (long)a->req.policySz);
    }
    return a->policy;
}

/* Set the nonce of a time-stamp request.
 *
 * The nonce is copied. It must be a non-negative INTEGER - a negative nonce
 * is rejected.
 *
 * @param [in, out] a      TS_REQ object.
 * @param [in]      nonce  Nonce to send.
 * @return  1 on success.
 * @return  0 on failure or when nonce is negative.
 */
int wolfSSL_TS_REQ_set_nonce(WOLFSSL_TS_REQ* a,
    const WOLFSSL_ASN1_INTEGER* nonce)
{
    const unsigned char* data = NULL;
    word32 len = 0;

    if ((a == NULL) || (nonce == NULL))
        return 0;
    /* Get the value bytes out of the ASN.1 INTEGER and store in the wc
     * request - leading zero bytes are stripped by wc_TspRequest_SetNonce. */
    if (ts_asn1_integer_get(nonce, &data, &len) != 1)
        return 0;
    if (wc_TspRequest_SetNonce(&a->req, data, len) != 0)
        return 0;

    /* Discard any cached view so it is rebuilt from the wc request. */
    if (a->nonce != NULL) {
        wolfSSL_ASN1_INTEGER_free(a->nonce);
        a->nonce = NULL;
    }

    return 1;
}

/* Get the nonce of a time-stamp request.
 *
 * @param [in] a  TS_REQ object.
 * @return  Nonce of the object - do not free.
 * @return  NULL when a is NULL or no nonce set.
 */
const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_REQ_get_nonce(const WOLFSSL_TS_REQ* a)
{
    WOLFSSL_TS_REQ* req = (WOLFSSL_TS_REQ*)a;

    if ((a == NULL) || (a->req.nonceSz == 0))
        return NULL;
    if (req->nonce == NULL)
        req->nonce = wolfssl_asn1_integer_new_buf(a->req.nonce, a->req.nonceSz);
    return req->nonce;
}

/* Set whether the TSA's certificate is requested in the response.
 *
 * @param [in, out] a        TS_REQ object.
 * @param [in]      certReq  Request certificate when non-zero.
 * @return  1 on success.
 * @return  0 when a is NULL.
 */
int wolfSSL_TS_REQ_set_cert_req(WOLFSSL_TS_REQ* a, int certReq)
{
    if (a == NULL)
        return 0;
    a->req.certReq = (byte)(certReq != 0);
    return 1;
}

/* Get whether the TSA's certificate is requested in the response.
 *
 * @param [in] a  TS_REQ object.
 * @return  1 when certificate requested.
 * @return  0 when not requested or a is NULL.
 */
int wolfSSL_TS_REQ_get_cert_req(const WOLFSSL_TS_REQ* a)
{
    if (a == NULL)
        return 0;
    return a->req.certReq;
}

/* Encode a time-stamp request.
 *
 * @param [in]      a   TS_REQ object.
 * @param [in, out] pp  Output buffer pointer. May be NULL. When pointer to
 *                      NULL, a buffer is allocated and not advanced.
 *                      Otherwise written to and advanced.
 * @return  Length of encoding on success.
 * @return  -1 on failure.
 */
int wolfSSL_i2d_TS_REQ(const WOLFSSL_TS_REQ* a, unsigned char** pp)
{
    int ret = -1;
    unsigned char* der = NULL;
    word32 derSz = 0;

    WOLFSSL_ENTER("wolfSSL_i2d_TS_REQ");

    if (a == NULL)
        return -1;

    /* Encode the wc request into a new buffer and return in i2d style. */
    if (wc_TspRequest_Encode(&a->req, NULL, &derSz) != 0) {
        return -1;
    }
    if (pp == NULL)
        return (int)derSz;

    der = *pp;
    if (der == NULL) {
        der = (unsigned char*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_OPENSSL);
    }
    if (der == NULL)
       return -1;
    if (wc_TspRequest_Encode(&a->req, der, &derSz) == 0) {
        ret = (int)derSz;
        *pp = (*pp != der) ? der : der + derSz;
    }
    else if (der != *pp)
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);

    return ret;
}

/* Decode a time-stamp request.
 *
 * @param [in, out] a       TS_REQ object pointer. May be NULL. Any object
 *                          pointed to is freed and replaced.
 * @param [in, out] pp      Pointer to DER encoding - advanced past the
 *                          request.
 * @param [in]      length  Length of data in buffer in bytes.
 * @return  TS_REQ object on success.
 * @return  NULL on failure.
 */
WOLFSSL_TS_REQ* wolfSSL_d2i_TS_REQ(WOLFSSL_TS_REQ** a,
    const unsigned char** pp, long length)
{
    WOLFSSL_TS_REQ* ret;
    word32 sz;

    WOLFSSL_ENTER("wolfSSL_d2i_TS_REQ");

    if ((pp == NULL) || (*pp == NULL))
        return NULL;
    sz = ts_msg_len(*pp, length);
    if (sz == 0)
        return NULL;

    ret = wolfSSL_TS_REQ_new();
    if (ret == NULL)
        return NULL;

    /* Decode straight into the wc request. */
    if (wc_TspRequest_Decode(&ret->req, *pp, sz) != 0) {
        wolfSSL_TS_REQ_free(ret);
        return NULL;
    }

    *pp += sz;
    if (a != NULL) {
        wolfSSL_TS_REQ_free(*a);
        *a = ret;
    }
    return ret;
}

#endif /* WOLFSSL_TSP_REQUESTER */

/******************************************************************************
 * TS_STATUS_INFO and TS_ACCURACY
 *****************************************************************************/

/* Get the PKIStatus of a status info.
 *
 * @param [in] a  TS_STATUS_INFO object.
 * @return  Status of the object - do not free.
 * @return  NULL when a is NULL.
 */
const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_STATUS_INFO_get0_status(
    const WOLFSSL_TS_STATUS_INFO* a)
{
    WOLFSSL_TS_STATUS_INFO* info = (WOLFSSL_TS_STATUS_INFO*)a;

    if (a == NULL)
        return NULL;
    if (info->status == NULL)
        info->status = ts_asn1_integer_new_num((long)a->resp->status);
    return info->status;
}

/* Get the failure information of a status info.
 *
 * @param [in] a  TS_STATUS_INFO object.
 * @return  Failure information of the object - do not free.
 * @return  NULL when a is NULL or no failure information.
 */
const WOLFSSL_ASN1_BIT_STRING* wolfSSL_TS_STATUS_INFO_get0_failure_info(
    const WOLFSSL_TS_STATUS_INFO* a)
{
    WOLFSSL_TS_STATUS_INFO* info = (WOLFSSL_TS_STATUS_INFO*)a;

    if ((a == NULL) || (a->resp->failInfo == 0))
        return NULL;

    if (info->failInfo == NULL) {
        WOLFSSL_ASN1_BIT_STRING* bs = wolfSSL_ASN1_BIT_STRING_new();
        unsigned char b[4];
        word32 i;
        int n = 0;

        if (bs == NULL)
            return NULL;
        /* Big-endian bytes of number - trailing zero bytes not encoded. */
        for (i = 0; i < 4; i++) {
            b[i] = (unsigned char)(a->resp->failInfo >> (8 * (3 - i)));
            if (b[i] != 0) {
                n = (int)i + 1;
            }
        }
        if (wolfSSL_ASN1_BIT_STRING_set1(bs, b, n) != 1) {
            wolfSSL_ASN1_BIT_STRING_free(bs);
            return NULL;
        }
        bs->type = ASN_BIT_STRING;
        info->failInfo = bs;
    }

    return info->failInfo;
}

/* Get the status string (PKIFreeText) of a status info.
 *
 * Only the first UTF8String of the PKIFreeText is in the stack.
 *
 * @param [in] a  TS_STATUS_INFO object.
 * @return  Stack of ASN1_UTF8STRINGs - do not free.
 * @return  NULL when a is NULL or no status string present.
 */
const WOLF_STACK_OF(WOLFSSL_ASN1_STRING)* wolfSSL_TS_STATUS_INFO_get0_text(
    const WOLFSSL_TS_STATUS_INFO* a)
{
    WOLFSSL_TS_STATUS_INFO* info = (WOLFSSL_TS_STATUS_INFO*)a;

    if ((a == NULL) || (a->resp->statusString == NULL))
        return NULL;

    if (info->text == NULL) {
        WOLFSSL_ASN1_STRING* str;
        WOLFSSL_STACK* sk;

        str = wolfSSL_ASN1_STRING_new();
        if (str == NULL)
            return NULL;
        /* Reference the first UTF8String in the response's der. */
        str->type = WOLFSSL_V_ASN1_UTF8STRING;
        str->data = (char*)a->resp->statusString;
        str->length = (int)a->resp->statusStringSz;
        str->isDynamic = 0;

        sk = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK), NULL,
            DYNAMIC_TYPE_OPENSSL);
        if (sk == NULL) {
            wolfSSL_ASN1_STRING_free(str);
            return NULL;
        }
        XMEMSET(sk, 0, sizeof(WOLFSSL_STACK));
        sk->num = 1;
        sk->type = STACK_TYPE_NULL;
        sk->data.generic = str;

        info->textStr = str;
        info->text = sk;
    }

    return info->text;
}

/* Get the seconds of an accuracy.
 *
 * @param [in] a  TS_ACCURACY object.
 * @return  Seconds of the object - do not free.
 * @return  NULL when a is NULL or seconds not present.
 */
const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_ACCURACY_get_seconds(
    const WOLFSSL_TS_ACCURACY* a)
{
    WOLFSSL_TS_ACCURACY* acc = (WOLFSSL_TS_ACCURACY*)a;

    if ((a == NULL) || (a->acc->seconds == 0))
        return NULL;
    if (acc->seconds == NULL)
        acc->seconds = ts_asn1_integer_new_num((long)a->acc->seconds);
    return acc->seconds;
}

/* Get the milliseconds of an accuracy.
 *
 * @param [in] a  TS_ACCURACY object.
 * @return  Milliseconds of the object - do not free.
 * @return  NULL when a is NULL or milliseconds not present.
 */
const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_ACCURACY_get_millis(
    const WOLFSSL_TS_ACCURACY* a)
{
    WOLFSSL_TS_ACCURACY* acc = (WOLFSSL_TS_ACCURACY*)a;

    if ((a == NULL) || (a->acc->millis == 0))
        return NULL;
    if (acc->millis == NULL)
        acc->millis = ts_asn1_integer_new_num((long)a->acc->millis);
    return acc->millis;
}

/* Get the microseconds of an accuracy.
 *
 * @param [in] a  TS_ACCURACY object.
 * @return  Microseconds of the object - do not free.
 * @return  NULL when a is NULL or microseconds not present.
 */
const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_ACCURACY_get_micros(
    const WOLFSSL_TS_ACCURACY* a)
{
    WOLFSSL_TS_ACCURACY* acc = (WOLFSSL_TS_ACCURACY*)a;

    if ((a == NULL) || (a->acc->micros == 0))
        return NULL;
    if (acc->micros == NULL)
        acc->micros = ts_asn1_integer_new_num((long)a->acc->micros);
    return acc->micros;
}

/* Dispose of an accuracy view.
 *
 * @param [in, out] a  TS_ACCURACY object. May be NULL.
 */
static void ts_accuracy_free(WOLFSSL_TS_ACCURACY* a)
{
    if (a != NULL) {
        wolfSSL_ASN1_INTEGER_free(a->seconds);
        wolfSSL_ASN1_INTEGER_free(a->millis);
        wolfSSL_ASN1_INTEGER_free(a->micros);
        XFREE(a, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

/* Dispose of a status info view.
 *
 * @param [in, out] a  TS_STATUS_INFO object. May be NULL.
 */
static void ts_status_info_free(WOLFSSL_TS_STATUS_INFO* a)
{
    if (a != NULL) {
        wolfSSL_ASN1_INTEGER_free(a->status);
        wolfSSL_ASN1_BIT_STRING_free(a->failInfo);
        wolfSSL_ASN1_STRING_free(a->textStr);
        XFREE(a->text, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(a, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

/******************************************************************************
 * TS_TST_INFO
 *****************************************************************************/

/* Dispose of a TSTInfo.
 *
 * @param [in, out] a  TS_TST_INFO object. May be NULL.
 */
void wolfSSL_TS_TST_INFO_free(WOLFSSL_TS_TST_INFO* a)
{
    if (a != NULL) {
        XFREE(a->der, NULL, DYNAMIC_TYPE_OPENSSL);
        wolfSSL_ASN1_OBJECT_free(a->policy);
        wolfSSL_TS_MSG_IMPRINT_free(a->msgImprint);
        wolfSSL_ASN1_INTEGER_free(a->serial);
        wolfSSL_ASN1_TIME_free(a->time);
        ts_accuracy_free(a->accuracy);
        wolfSSL_ASN1_INTEGER_free(a->nonce);
        wolfSSL_GENERAL_NAME_free(a->tsa);
        XFREE(a, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

/* Create a TS_TST_INFO from the DER encoding.
 *
 * @param [in] der  DER encoding of TSTInfo.
 * @param [in] sz   Length of encoding in bytes.
 * @return  TS_TST_INFO object on success.
 * @return  NULL on failure.
 */
static WOLFSSL_TS_TST_INFO* ts_tst_info_from_der(const unsigned char* der,
    word32 sz)
{
    WOLFSSL_TS_TST_INFO* ret;

    ret = (WOLFSSL_TS_TST_INFO*)XMALLOC(sizeof(WOLFSSL_TS_TST_INFO), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (ret == NULL)
        return NULL;
    XMEMSET(ret, 0, sizeof(WOLFSSL_TS_TST_INFO));

    /* Keep a copy of the encoding - the wc TSTInfo references into it. */
    ret->der = (unsigned char*)XMALLOC(sz, NULL, DYNAMIC_TYPE_OPENSSL);
    if (ret->der == NULL) {
        XFREE(ret, NULL, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }
    XMEMCPY(ret->der, der, sz);
    ret->derSz = sz;

    /* Decode straight into the wc TSTInfo. */
    if (wc_TspTstInfo_Decode(&ret->tst, ret->der, sz) != 0) {
        wolfSSL_TS_TST_INFO_free(ret);
        return NULL;
    }

    return ret;
}

/* Decode a TSTInfo.
 *
 * @param [in, out] a       TS_TST_INFO object pointer. May be NULL. Any
 *                          object pointed to is freed and replaced.
 * @param [in, out] pp      Pointer to DER encoding - advanced past the
 *                          TSTInfo.
 * @param [in]      length  Length of data in buffer in bytes.
 * @return  TS_TST_INFO object on success.
 * @return  NULL on failure.
 */
WOLFSSL_TS_TST_INFO* wolfSSL_d2i_TS_TST_INFO(WOLFSSL_TS_TST_INFO** a,
    const unsigned char** pp, long length)
{
    WOLFSSL_TS_TST_INFO* ret;
    word32 sz;

    WOLFSSL_ENTER("wolfSSL_d2i_TS_TST_INFO");

    if ((pp == NULL) || (*pp == NULL))
        return NULL;
    sz = ts_msg_len(*pp, length);
    if (sz == 0)
        return NULL;

    ret = ts_tst_info_from_der(*pp, sz);
    if (ret == NULL)
        return NULL;

    *pp += sz;
    if (a != NULL) {
        wolfSSL_TS_TST_INFO_free(*a);
        *a = ret;
    }
    return ret;
}

/* Encode a TSTInfo.
 *
 * @param [in]      a   TS_TST_INFO object.
 * @param [in, out] pp  Output buffer pointer. May be NULL. When pointer to
 *                      NULL, a buffer is allocated and not advanced.
 *                      Otherwise written to and advanced.
 * @return  Length of encoding on success.
 * @return  -1 on failure.
 */
int wolfSSL_i2d_TS_TST_INFO(const WOLFSSL_TS_TST_INFO* a, unsigned char** pp)
{
    if (a == NULL)
        return -1;
    return ts_i2d(a->der, a->derSz, pp);
}

/* Get the version of a TSTInfo.
 *
 * @param [in] a  TS_TST_INFO object.
 * @return  Version of TSTInfo.
 * @return  0 when a is NULL.
 */
long wolfSSL_TS_TST_INFO_get_version(const WOLFSSL_TS_TST_INFO* a)
{
    if (a == NULL)
        return 0;
    return (long)a->tst.version;
}

/* Get the TSA policy of a TSTInfo.
 *
 * @param [in] a  TS_TST_INFO object.
 * @return  TSA policy ID of the object - do not free.
 * @return  NULL when a is NULL.
 */
WOLFSSL_ASN1_OBJECT* wolfSSL_TS_TST_INFO_get_policy_id(WOLFSSL_TS_TST_INFO* a)
{
    if (a == NULL)
        return NULL;
    /* Build the object from the OID content in the wc TSTInfo. */
    if ((a->policy == NULL) && (a->tst.policy != NULL)) {
        const unsigned char* p = a->tst.policy;
        a->policy = wolfSSL_c2i_ASN1_OBJECT(NULL, &p, (long)a->tst.policySz);
    }
    return a->policy;
}

/* Get the message imprint of a TSTInfo.
 *
 * @param [in] a  TS_TST_INFO object.
 * @return  Message imprint of the object - do not free.
 * @return  NULL when a is NULL.
 */
WOLFSSL_TS_MSG_IMPRINT* wolfSSL_TS_TST_INFO_get_msg_imprint(
    WOLFSSL_TS_TST_INFO* a)
{
    if (a == NULL)
        return NULL;
    if (a->msgImprint == NULL)
        a->msgImprint = ts_msg_imprint_new(&a->tst.imprint);
    return a->msgImprint;
}

/* Get the serial number of a TSTInfo.
 *
 * @param [in] a  TS_TST_INFO object.
 * @return  Serial number of the object - do not free.
 * @return  NULL when a is NULL.
 */
const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_TST_INFO_get_serial(
    const WOLFSSL_TS_TST_INFO* a)
{
    WOLFSSL_TS_TST_INFO* tst = (WOLFSSL_TS_TST_INFO*)a;

    if (a == NULL)
        return NULL;
    if ((tst->serial == NULL) && (a->tst.serial != NULL)) {
        tst->serial = wolfssl_asn1_integer_new_buf(a->tst.serial,
                                                   a->tst.serialSz);
    }
    return tst->serial;
}

/* Get the time of the time-stamp of a TSTInfo.
 *
 * @param [in] a  TS_TST_INFO object.
 * @return  Time of the object - do not free.
 * @return  NULL when a is NULL.
 */
const WOLFSSL_ASN1_GENERALIZEDTIME* wolfSSL_TS_TST_INFO_get_time(
    const WOLFSSL_TS_TST_INFO* a)
{
    WOLFSSL_TS_TST_INFO* tst = (WOLFSSL_TS_TST_INFO*)a;

    if (a == NULL)
        return NULL;
    if ((tst->time == NULL) && (a->tst.genTime != NULL) &&
            (a->tst.genTimeSz < (word32)CTC_DATE_SIZE)) {
        WOLFSSL_ASN1_TIME* t = wolfSSL_ASN1_TIME_new();
        if (t != NULL) {
            t->type = WOLFSSL_V_ASN1_GENERALIZEDTIME;
            t->length = (int)a->tst.genTimeSz;
            XMEMCPY(t->data, a->tst.genTime, a->tst.genTimeSz);
        }
        tst->time = t;
    }
    return tst->time;
}

/* Get the accuracy of a TSTInfo.
 *
 * @param [in] a  TS_TST_INFO object.
 * @return  Accuracy of the object - do not free.
 * @return  NULL when a is NULL or accuracy not present.
 */
WOLFSSL_TS_ACCURACY* wolfSSL_TS_TST_INFO_get_accuracy(WOLFSSL_TS_TST_INFO* a)
{
    if (a == NULL)
        return NULL;
    /* Accuracy is absent when all parts are zero. */
    if ((a->tst.accuracy.seconds == 0) && (a->tst.accuracy.millis == 0) &&
            (a->tst.accuracy.micros == 0))
        return NULL;

    if (a->accuracy == NULL) {
        WOLFSSL_TS_ACCURACY* acc = (WOLFSSL_TS_ACCURACY*)XMALLOC(
            sizeof(WOLFSSL_TS_ACCURACY), NULL, DYNAMIC_TYPE_OPENSSL);
        if (acc == NULL)
            return NULL;
        XMEMSET(acc, 0, sizeof(WOLFSSL_TS_ACCURACY));
        acc->acc = &a->tst.accuracy;
        a->accuracy = acc;
    }

    return a->accuracy;
}

/* Get whether time-stamps from the TSA are strictly ordered.
 *
 * @param [in] a  TS_TST_INFO object.
 * @return  1 when strictly ordered.
 * @return  0 when not ordered or a is NULL.
 */
int wolfSSL_TS_TST_INFO_get_ordering(const WOLFSSL_TS_TST_INFO* a)
{
    if (a == NULL)
        return 0;
    return a->tst.ordering;
}

/* Get the nonce of a TSTInfo.
 *
 * @param [in] a  TS_TST_INFO object.
 * @return  Nonce of the object - do not free.
 * @return  NULL when a is NULL or no nonce present.
 */
const WOLFSSL_ASN1_INTEGER* wolfSSL_TS_TST_INFO_get_nonce(
    const WOLFSSL_TS_TST_INFO* a)
{
    WOLFSSL_TS_TST_INFO* tst = (WOLFSSL_TS_TST_INFO*)a;

    if ((a == NULL) || (a->tst.nonce == NULL))
        return NULL;
    if (tst->nonce == NULL)
        tst->nonce = wolfssl_asn1_integer_new_buf(a->tst.nonce, a->tst.nonceSz);
    return tst->nonce;
}

/* Get the TSA name of a TSTInfo as a GeneralName.
 *
 * Builds a GENERAL_NAME from the TSTInfo's tsa field on the first call and
 * caches it on the object. directoryName, dNSName, rfc822Name and
 * uniformResourceIdentifier forms are supported.
 *
 * @param [in] a  TS_TST_INFO object.
 * @return  GeneralName of the TSA - owned by the object, do not free.
 * @return  NULL when a is NULL, no TSA name is present or the form is not
 *          supported.
 */
WOLFSSL_GENERAL_NAME* wolfSSL_TS_TST_INFO_get_tsa(WOLFSSL_TS_TST_INFO* a)
{
    WOLFSSL_GENERAL_NAME* gn;
    const byte* tsa;
    word32 idx = 1;
    int len = 0;
    byte tag;

    if ((a == NULL) || (a->tst.tsa == NULL) || (a->tst.tsaSz == 0))
        return NULL;
    /* Return the cached view when already built. */
    if (a->tsa != NULL)
        return a->tsa;

    tsa = a->tst.tsa;
    tag = tsa[0];
    /* The GeneralName content follows the tag and length at tsa[idx]. */
    if (GetLength(tsa, &idx, &len, a->tst.tsaSz) < 0)
        return NULL;

    gn = wolfSSL_GENERAL_NAME_new();
    if (gn == NULL)
        return NULL;

    if (tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | ASN_DIR_TYPE)) {
        /* directoryName [4] - the content is a Name (SEQUENCE). */
        const unsigned char* p = tsa + idx;
        WOLFSSL_X509_NAME* name = wolfSSL_d2i_X509_NAME(NULL,
            (unsigned char**)&p, len);

        if (name == NULL) {
            wolfSSL_GENERAL_NAME_free(gn);
            return NULL;
        }
        /* Replace the default IA5 string with the directory name. */
        wolfSSL_ASN1_STRING_free(gn->d.ia5);
        gn->type = WOLFSSL_GEN_DIRNAME;
        gn->d.dirn = name;
    }
    else if ((tag == (ASN_CONTEXT_SPECIFIC | ASN_RFC822_TYPE)) ||
             (tag == (ASN_CONTEXT_SPECIFIC | ASN_DNS_TYPE)) ||
             (tag == (ASN_CONTEXT_SPECIFIC | ASN_URI_TYPE))) {
        /* rfc822Name [1], dNSName [2] or uniformResourceIdentifier [6] - an
         * IA5String. The CHOICE number matches the GENERAL_NAME type and
         * uses the default IA5 string of the new GeneralName. */
        if (wolfSSL_ASN1_STRING_set(gn->d.ia5, tsa + idx, len) != 1) {
            wolfSSL_GENERAL_NAME_free(gn);
            return NULL;
        }
        gn->type = (int)(tag & ~ASN_CONTEXT_SPECIFIC);
    }
    else {
        /* Unsupported GeneralName form. */
        wolfSSL_GENERAL_NAME_free(gn);
        return NULL;
    }

    a->tsa = gn;
    return gn;
}

/******************************************************************************
 * TS_RESP
 *****************************************************************************/

/* Dispose of a time-stamp response.
 *
 * @param [in, out] a  TS_RESP object. May be NULL.
 */
void wolfSSL_TS_RESP_free(WOLFSSL_TS_RESP* a)
{
    if (a != NULL) {
        XFREE(a->der, NULL, DYNAMIC_TYPE_OPENSSL);
        ts_status_info_free(a->statusInfo);
        wolfSSL_TS_TST_INFO_free(a->tstInfo);
        XFREE(a, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

/* Decode a time-stamp response.
 *
 * @param [in, out] a       TS_RESP object pointer. May be NULL. Any object
 *                          pointed to is freed and replaced.
 * @param [in, out] pp      Pointer to DER encoding - advanced past the
 *                          response.
 * @param [in]      length  Length of data in buffer in bytes.
 * @return  TS_RESP object on success.
 * @return  NULL on failure.
 */
WOLFSSL_TS_RESP* wolfSSL_d2i_TS_RESP(WOLFSSL_TS_RESP** a,
    const unsigned char** pp, long length)
{
    WOLFSSL_TS_RESP* ret;
    word32 sz;

    WOLFSSL_ENTER("wolfSSL_d2i_TS_RESP");

    if ((pp == NULL) || (*pp == NULL))
        return NULL;
    sz = ts_msg_len(*pp, length);
    if (sz == 0)
        return NULL;

    ret = (WOLFSSL_TS_RESP*)XMALLOC(sizeof(WOLFSSL_TS_RESP), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (ret == NULL)
        return NULL;
    XMEMSET(ret, 0, sizeof(WOLFSSL_TS_RESP));

    /* Keep a copy of the encoding - the wc response references into it. */
    ret->der = (unsigned char*)XMALLOC(sz, NULL, DYNAMIC_TYPE_OPENSSL);
    if (ret->der == NULL) {
        wolfSSL_TS_RESP_free(ret);
        return NULL;
    }

    XMEMCPY(ret->der, *pp, sz);
    ret->derSz = sz;
    if (wc_TspResponse_Decode(&ret->resp, ret->der, sz) != 0) {
        wolfSSL_TS_RESP_free(ret);
        return NULL;
    }

    *pp += sz;
    if (a != NULL) {
        wolfSSL_TS_RESP_free(*a);
        *a = ret;
    }
    return ret;
}

/* Encode a time-stamp response.
 *
 * @param [in]      a   TS_RESP object.
 * @param [in, out] pp  Output buffer pointer. May be NULL. When pointer to
 *                      NULL, a buffer is allocated and not advanced.
 *                      Otherwise written to and advanced.
 * @return  Length of encoding on success.
 * @return  -1 on failure.
 */
int wolfSSL_i2d_TS_RESP(const WOLFSSL_TS_RESP* a, unsigned char** pp)
{
    if (a == NULL)
        return -1;
    return ts_i2d(a->der, a->derSz, pp);
}

/* Get the status info of a time-stamp response.
 *
 * @param [in] a  TS_RESP object.
 * @return  Status info of the object - do not free.
 * @return  NULL when a is NULL.
 */
WOLFSSL_TS_STATUS_INFO* wolfSSL_TS_RESP_get_status_info(WOLFSSL_TS_RESP* a)
{
    if (a == NULL)
        return NULL;

    if (a->statusInfo == NULL) {
        WOLFSSL_TS_STATUS_INFO* info = (WOLFSSL_TS_STATUS_INFO*)XMALLOC(
            sizeof(WOLFSSL_TS_STATUS_INFO), NULL, DYNAMIC_TYPE_OPENSSL);
        if (info == NULL)
            return NULL;
        XMEMSET(info, 0, sizeof(WOLFSSL_TS_STATUS_INFO));
        info->resp = &a->resp;
        a->statusInfo = info;
    }

    return a->statusInfo;
}

/* Get the TSTInfo of the token of a time-stamp response.
 *
 * The token's signature must verify for the TSTInfo to be available.
 *
 * @param [in] a  TS_RESP object.
 * @return  TSTInfo of the object - do not free.
 * @return  NULL when a is NULL or there is no valid token.
 */
WOLFSSL_TS_TST_INFO* wolfSSL_TS_RESP_get_tst_info(WOLFSSL_TS_RESP* a)
{
    if (a == NULL)
        return NULL;

    /* Get the TSTInfo out of the token on first use. */
    if ((a->tstInfo == NULL) && (a->resp.token != NULL)) {
        wc_PKCS7* pkcs7;

        pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
        if (pkcs7 != NULL) {
            TspTstInfo tst;

            if ((wc_PKCS7_InitWithCert(pkcs7, NULL, 0) == 0) &&
                    (wc_TspTstInfo_VerifyWithPKCS7(pkcs7, (byte*)a->resp.token,
                        a->resp.tokenSz, &tst) == 0)) {
                a->tstInfo = ts_tst_info_from_der(pkcs7->content,
                    pkcs7->contentSz);
            }
            wc_PKCS7_Free(pkcs7);
        }
    }

    return a->tstInfo;
}

/******************************************************************************
 * TS_VERIFY_CTX
 *****************************************************************************/

/* Create a new verification context.
 *
 * @return  TS_VERIFY_CTX object on success.
 * @return  NULL on failure.
 */
WOLFSSL_TS_VERIFY_CTX* wolfSSL_TS_VERIFY_CTX_new(void)
{
    WOLFSSL_TS_VERIFY_CTX* ctx;

    ctx = (WOLFSSL_TS_VERIFY_CTX*)XMALLOC(sizeof(WOLFSSL_TS_VERIFY_CTX),
        NULL, DYNAMIC_TYPE_OPENSSL);
    if (ctx != NULL) {
        XMEMSET(ctx, 0, sizeof(WOLFSSL_TS_VERIFY_CTX));
    }

    return ctx;
}

/* Free the items of a verification context.
 *
 * @param [in, out] ctx  TS_VERIFY_CTX object. May be NULL.
 */
void wolfSSL_TS_VERIFY_CTX_cleanup(WOLFSSL_TS_VERIFY_CTX* ctx)
{
    if (ctx != NULL) {
        wolfSSL_X509_STORE_free(ctx->store);
        XFREE(ctx->imprint, NULL, DYNAMIC_TYPE_OPENSSL);
        wolfSSL_BIO_free(ctx->data);
        XMEMSET(ctx, 0, sizeof(WOLFSSL_TS_VERIFY_CTX));
    }
}

/* Dispose of a verification context.
 *
 * @param [in, out] ctx  TS_VERIFY_CTX object. May be NULL.
 */
void wolfSSL_TS_VERIFY_CTX_free(WOLFSSL_TS_VERIFY_CTX* ctx)
{
    if (ctx != NULL) {
        wolfSSL_TS_VERIFY_CTX_cleanup(ctx);
        XFREE(ctx, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

/* Set the checks to perform when verifying.
 *
 * @param [in, out] ctx    TS_VERIFY_CTX object.
 * @param [in]      flags  TS_VFY_* flags of checks to perform.
 * @return  Flags set.
 * @return  0 when ctx is NULL.
 */
int wolfSSL_TS_VERIFY_CTX_set_flags(WOLFSSL_TS_VERIFY_CTX* ctx, int flags)
{
    if (ctx == NULL)
        return 0;
    ctx->flags = (unsigned int)flags;
    return (int)ctx->flags;
}

/* Add to the checks to perform when verifying.
 *
 * @param [in, out] ctx    TS_VERIFY_CTX object.
 * @param [in]      flags  TS_VFY_* flags of checks to add.
 * @return  Flags set.
 * @return  0 when ctx is NULL.
 */
int wolfSSL_TS_VERIFY_CTX_add_flags(WOLFSSL_TS_VERIFY_CTX* ctx, int flags)
{
    if (ctx == NULL)
        return 0;
    ctx->flags |= (unsigned int)flags;
    return (int)ctx->flags;
}

/* Set the expected hash of the message imprint.
 *
 * Takes ownership of imprint - disposed of when the context is.
 *
 * @param [in, out] ctx      TS_VERIFY_CTX object.
 * @param [in]      imprint  Allocated hash of message.
 * @param [in]      len      Length of hash in bytes.
 * @return  The imprint set.
 * @return  NULL when ctx is NULL.
 */
unsigned char* wolfSSL_TS_VERIFY_CTX_set_imprint(WOLFSSL_TS_VERIFY_CTX* ctx,
    unsigned char* imprint, long len)
{
    if (ctx == NULL)
        return NULL;
    XFREE(ctx->imprint, NULL, DYNAMIC_TYPE_OPENSSL);
    /* Takes ownership of imprint. */
    ctx->imprint = imprint;
    ctx->imprintSz = (word32)len;
    return ctx->imprint;
}

/* Set the data to hash and check against the message imprint for TS_VFY_DATA.
 *
 * Takes ownership of the BIO - freed when the context is cleaned up, matching
 * OpenSSL. The data is read and hashed during verification.
 *
 * @param [in, out] ctx  TS_VERIFY_CTX object.
 * @param [in]      b    BIO to read the time-stamped data from. May be NULL.
 * @return  The BIO set.
 * @return  NULL when ctx is NULL.
 */
WOLFSSL_BIO* wolfSSL_TS_VERIFY_CTX_set_data(WOLFSSL_TS_VERIFY_CTX* ctx,
    WOLFSSL_BIO* b)
{
    if (ctx == NULL)
        return NULL;
    if (ctx->data != b) {
        /* Replace and take ownership of the new BIO. */
        wolfSSL_BIO_free(ctx->data);
        ctx->data = b;
    }
    return ctx->data;
}

/* Set the store of trusted certificates to check the signer against.
 *
 * Takes ownership of store - disposed of when the context is.
 *
 * @param [in, out] ctx    TS_VERIFY_CTX object.
 * @param [in]      store  Store of trusted certificates. May be NULL.
 * @return  The store set.
 * @return  NULL when ctx is NULL or clearing the store.
 */
WOLFSSL_X509_STORE* wolfSSL_TS_VERIFY_CTX_set_store(
    WOLFSSL_TS_VERIFY_CTX* ctx, WOLFSSL_X509_STORE* store)
{
    if (ctx == NULL)
        return NULL;
    wolfSSL_X509_STORE_free(ctx->store);
    /* Takes ownership of store. */
    ctx->store = store;
    return ctx->store;
}

#ifdef WOLFSSL_TSP_REQUESTER
/* Fill a verification context from the request sent.
 *
 * The message imprint's hash, nonce and policy are copied and all checks
 * but the TSA name are enabled.
 *
 * @param [in]      req  TS_REQ object sent.
 * @param [in, out] ctx  TS_VERIFY_CTX object to fill. When NULL a new
 *                       object is created.
 * @return  TS_VERIFY_CTX object on success.
 * @return  NULL on failure.
 */
WOLFSSL_TS_VERIFY_CTX* wolfSSL_TS_REQ_to_TS_VERIFY_CTX(WOLFSSL_TS_REQ* req,
    WOLFSSL_TS_VERIFY_CTX* ctx)
{
    WOLFSSL_TS_VERIFY_CTX* ret = ctx;

    WOLFSSL_ENTER("wolfSSL_TS_REQ_to_TS_VERIFY_CTX");

    if (req == NULL)
        return NULL;
    /* A message imprint hash is required to verify against. */
    if (req->req.imprint.hashSz == 0)
        return NULL;
    if (ret == NULL)
        ret = wolfSSL_TS_VERIFY_CTX_new();
    if (ret == NULL)
        return NULL;

    /* Replace - not accumulate - the checks when reusing a context. */
    ret->flags = WOLFSSL_TS_VFY_ALL_IMPRINT & ~WOLFSSL_TS_VFY_TSA_NAME;

    /* Copy the message imprint's hash of the request. */
    XFREE(ret->imprint, NULL, DYNAMIC_TYPE_OPENSSL);
    ret->imprintSz = req->req.imprint.hashSz;
    ret->imprint = (unsigned char*)XMALLOC(ret->imprintSz, NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (ret->imprint == NULL) {
        /* Keep a reused context consistent - no imprint means no size. */
        ret->imprintSz = 0;
        if (ctx == NULL)
            wolfSSL_TS_VERIFY_CTX_free(ret);
        return NULL;
    }

    XMEMCPY(ret->imprint, req->req.imprint.hash, ret->imprintSz);
    /* Copy the nonce - cleared to absent when the request has none. */
    ret->nonceSz = req->req.nonceSz;
    if (ret->nonceSz != 0) {
        XMEMCPY(ret->nonce, req->req.nonce, ret->nonceSz);
    }
    /* Copy the policy - cleared to absent when the request has none. */
    ret->policySz = req->req.policySz;
    if (ret->policySz != 0) {
        XMEMCPY(ret->policy, req->req.policy, ret->policySz);
    }

    return ret;
}
#endif /* WOLFSSL_TSP_REQUESTER */

/* Check the token signer's certificate chains to a trust anchor in the store.
 *
 * The certificates carried in the token are used as untrusted intermediate
 * certificates so a signer issued by an intermediate CA verifies - matching
 * OpenSSL's TS_RESP_verify. The store is not modified: any intermediates added
 * to the cert manager while building the chain are unloaded by
 * wolfSSL_X509_verify_cert().
 *
 * @param [in] store  Trust store holding the trusted anchors.
 * @param [in] pkcs7  PKCS7 that verified the token - holds the signer
 *                    certificate and the token's certificates.
 * @return  1 when the signer's certificate is trusted.
 * @return  0 when it is not trusted or on error.
 */
static int ts_verify_signer_trusted(WOLFSSL_X509_STORE* store, wc_PKCS7* pkcs7)
{
    int trusted = 0;
    WOLFSSL_X509* leaf = NULL;
    WOLFSSL_X509_STORE_CTX* storeCtx = NULL;
    WOLF_STACK_OF(WOLFSSL_X509)* inter = NULL;
    const byte* p;
    int i;

    /* The signer's certificate is the leaf to verify. */
    p = pkcs7->verifyCert;
    leaf = wolfSSL_d2i_X509(NULL, &p, (int)pkcs7->verifyCertSz);
    /* The token's other certificates are untrusted intermediates. */
    inter = wolfSSL_sk_X509_new_null();
    if ((leaf == NULL) || (inter == NULL)) {
        goto done;
    }
    for (i = 0; i < MAX_PKCS7_CERTS; i++) {
        WOLFSSL_X509* x;

        if ((pkcs7->cert[i] == NULL) || (pkcs7->certSz[i] == 0)) {
            continue;
        }
        /* The signer leaf is verified separately - do not add it again. */
        if ((pkcs7->certSz[i] == pkcs7->verifyCertSz) &&
                (XMEMCMP(pkcs7->cert[i], pkcs7->verifyCert,
                    pkcs7->verifyCertSz) == 0)) {
            continue;
        }
        p = pkcs7->cert[i];
        x = wolfSSL_d2i_X509(NULL, &p, (int)pkcs7->certSz[i]);
        if (x == NULL) {
            goto done;
        }
        if (wolfSSL_sk_X509_push(inter, x) <= 0) {
            wolfSSL_X509_free(x);
            goto done;
        }
    }

    /* Build and verify the chain from the leaf through the intermediates to a
     * trust anchor in the store. */
    storeCtx = wolfSSL_X509_STORE_CTX_new();
    if ((storeCtx != NULL) &&
            (wolfSSL_X509_STORE_CTX_init(storeCtx, store, leaf, inter) ==
                WOLFSSL_SUCCESS) &&
            (wolfSSL_X509_verify_cert(storeCtx) == WOLFSSL_SUCCESS)) {
        trusted = 1;
    }

done:
    wolfSSL_X509_STORE_CTX_free(storeCtx);
    wolfSSL_sk_X509_pop_free(inter, wolfSSL_X509_free);
    wolfSSL_X509_free(leaf);
    return trusted;
}

/* Hash the data read from a BIO with the token's message imprint algorithm
 * and compare to the imprint - the TS_VFY_DATA check. The data is hashed
 * incrementally so it need not be held in memory all at once.
 *
 * @param [in] bio  BIO to read the time-stamped data from.
 * @param [in] tst  Decoded TSTInfo with the expected message imprint.
 * @return  1 when the hash of the data matches the imprint.
 * @return  0 otherwise or on error.
 */
static int ts_check_data(WOLFSSL_BIO* bio, const TspTstInfo* tst)
{
    int ok = 0;
    int failed = 0;
    int n;
    enum wc_HashType hashType;
    int digestSz;
    wc_HashAlg hash;
    byte digest[WC_MAX_DIGEST_SIZE];
#define TSP_CHECK_DATA_BUF_SZ 256
#ifdef WOLFSSL_SMALL_STACK
    byte* buf = NULL;
#else
    byte buf[TSP_CHECK_DATA_BUF_SZ];
#endif

    /* Hash algorithm and digest size of the message imprint. */
    hashType = wc_OidGetHash((int)tst->imprint.hashAlgOID);
    digestSz = wc_HashGetDigestSize(hashType);
    if ((digestSz <= 0) || (tst->imprint.hashSz != (word32)digestSz)) {
        return 0;
    }

    if (wc_HashInit(&hash, hashType) != 0) {
        return 0;
    }

#ifdef WOLFSSL_SMALL_STACK
    buf = (byte*)XMALLOC(TSP_CHECK_DATA_BUF_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        wc_HashFree(&hash, hashType);
        return 0;
    }
#endif
    /* Hash the data in chunks until the BIO is exhausted. A non-positive read
     * ends the data: a wolfSSL memory BIO signals end-of-data with a negative
     * return (BIO_read cannot distinguish it from an I/O error), and OpenSSL's
     * own imprint check likewise stops on any non-positive read. */
    while ((n = wolfSSL_BIO_read(bio, buf, TSP_CHECK_DATA_BUF_SZ)) > 0) {
        if (wc_HashUpdate(&hash, hashType, buf, (word32)n) != 0) {
            failed = 1;
            break;
        }
    }
    if ((!failed) && (wc_HashFinal(&hash, hashType, digest) == 0) &&
            (XMEMCMP(digest, tst->imprint.hash, (word32)digestSz) == 0)) {
        ok = 1;
    }
    wc_HashFree(&hash, hashType);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ok;
}
#undef TSP_CHECK_DATA_BUF_SZ

/* Verify a time-stamp token against the expected values in the context.
 *
 * The token's signature, content type and signer's certificate are always
 * checked - the signer must be trusted when a store is set. The version,
 * message imprint, nonce and policy are checked as flagged.
 *
 * @param [in] ctx      TS_VERIFY_CTX object with checks and expected values.
 * @param [in] token    DER encoding of time-stamp token - CMS SignedData.
 * @param [in] tokenSz  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int ts_verify_token(WOLFSSL_TS_VERIFY_CTX* ctx, unsigned char* token,
    word32 tokenSz)
{
    int ret = 0;
    wc_PKCS7* pkcs7 = NULL;
    TspTstInfo tst;

    /* Verify the signature of the token and validity for time-stamping. */
    pkcs7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (pkcs7 == NULL)
        return 0;
    if ((wc_PKCS7_InitWithCert(pkcs7, NULL, 0) != 0) ||
            (wc_TspTstInfo_VerifyWithPKCS7(pkcs7, token, tokenSz, &tst) != 0)) {
        goto cleanup;
    }

    /* When signature/signer verification is requested a trust store is
     * required - without one the signer is only checked against the cert
     * embedded in the token, which establishes no trust. Fail closed. */
    if ((ctx->flags & (WOLFSSL_TS_VFY_SIGNATURE | WOLFSSL_TS_VFY_SIGNER)) &&
            ((ctx->store == NULL) || (ctx->store->cm == NULL))) {
        WOLFSSL_MSG("TS signer verification requested but no trust store set");
        goto cleanup;
    }
    /* Check the signer's certificate is trusted when a store is set, building
     * a chain through any intermediate certificates carried in the token. */
    if ((ctx->store != NULL) && (ctx->store->cm != NULL) &&
            (!ts_verify_signer_trusted(ctx->store, pkcs7))) {
        WOLFSSL_MSG("TS signer's certificate is not trusted");
        goto cleanup;
    }

    /* Only version 1 supported. */
    if ((ctx->flags & WOLFSSL_TS_VFY_VERSION) &&
            (tst.version != WC_TSP_VERSION)) {
        WOLFSSL_MSG("TS version is not 1");
        goto cleanup;
    }
    /* Check the message imprint's hash is the expected. */
    if ((ctx->flags & WOLFSSL_TS_VFY_IMPRINT) &&
            ((ctx->imprint == NULL) ||
             (tst.imprint.hashSz != ctx->imprintSz) ||
             (XMEMCMP(tst.imprint.hash, ctx->imprint,
                  ctx->imprintSz) != 0))) {
        WOLFSSL_MSG("TS message imprint doesn't match");
        goto cleanup;
    }
    /* Check the data, when provided, hashes to the message imprint. The data
     * is read from the BIO and hashed with the token's imprint algorithm. */
    if ((ctx->flags & WOLFSSL_TS_VFY_DATA) &&
            ((ctx->data == NULL) || (!ts_check_data(ctx->data, &tst)))) {
        WOLFSSL_MSG("TS data doesn't match the message imprint");
        goto cleanup;
    }
    /* Check the nonce is the expected when set. */
    if ((ctx->flags & WOLFSSL_TS_VFY_NONCE) && (ctx->nonceSz != 0) &&
            ((tst.nonce == NULL) || (tst.nonceSz != ctx->nonceSz) ||
             (XMEMCMP(tst.nonce, ctx->nonce, tst.nonceSz) != 0))) {
        WOLFSSL_MSG("TS nonce doesn't match");
        goto cleanup;
    }
    /* Check the policy is the expected when set. */
    if ((ctx->flags & WOLFSSL_TS_VFY_POLICY) && (ctx->policySz != 0) &&
            ((tst.policy == NULL) || (tst.policySz != ctx->policySz) ||
             (XMEMCMP(tst.policy, ctx->policy, tst.policySz) != 0))) {
        WOLFSSL_MSG("TS policy doesn't match");
        goto cleanup;
    }

    ret = 1;
cleanup:
    wc_PKCS7_Free(pkcs7);
    return ret;
}

/* Verify a time-stamp response.
 *
 * The time-stamp must have been granted and the token is verified against
 * the context - see ts_verify_token().
 *
 * @param [in] ctx       TS_VERIFY_CTX object with checks and expected
 *                       values.
 * @param [in] response  TS_RESP object to verify.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_TS_RESP_verify_response(WOLFSSL_TS_VERIFY_CTX* ctx,
    WOLFSSL_TS_RESP* response)
{
    WOLFSSL_ENTER("wolfSSL_TS_RESP_verify_response");

    if ((ctx == NULL) || (response == NULL))
        return 0;

    /* Time-stamp must have been granted. */
    if ((response->resp.status != WC_TSP_PKISTATUS_GRANTED) &&
            (response->resp.status != WC_TSP_PKISTATUS_GRANTED_WITH_MODS)) {
        WOLFSSL_MSG("TS status is not granted");
        return 0;
    }
    if (response->resp.token == NULL) {
        WOLFSSL_MSG("TS response has no time-stamp token");
        return 0;
    }

    return ts_verify_token(ctx, (byte*)response->resp.token,
        response->resp.tokenSz);
}

#ifdef OPENSSL_ALL
/* Verify a time-stamp token.
 *
 * The token's encoding, kept by d2i_PKCS7, is verified against the context -
 * see ts_verify_token().
 *
 * @param [in] ctx    TS_VERIFY_CTX object with checks and expected values.
 * @param [in] token  WOLFSSL_PKCS7 object holding a time-stamp token - the
 *                    extended object returned by d2i_PKCS7(), which keeps the
 *                    DER encoding needed here.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_TS_RESP_verify_token(WOLFSSL_TS_VERIFY_CTX* ctx,
    WOLFSSL_PKCS7* token)
{
    WOLFSSL_ENTER("wolfSSL_TS_RESP_verify_token");

    if ((ctx == NULL) || (token == NULL) || (token->data == NULL) ||
            (token->len <= 0)) {
        return 0;
    }

    return ts_verify_token(ctx, token->data, (word32)token->len);
}
#endif /* OPENSSL_ALL */

#ifdef WOLFSSL_TSP_RESPONDER
/******************************************************************************
 * TS_RESP_CTX - responder context for creating time-stamp responses.
 *****************************************************************************/

struct WOLFSSL_TS_RESP_CTX {
    /* Signer's certificate as DER - owned. */
    unsigned char* certDer;
    word32 certSz;
    /* Signer's private key as DER - owned. */
    unsigned char* keyDer;
    word32 keySz;
    /* Private key type - WC_PK_TYPE_RSA or WC_PK_TYPE_ECDSA_SIGN. */
    enum wc_PkType keyType;
    /* Signature hash algorithm. */
    enum wc_HashType hashType;
    /* Default TSA policy as OBJECT IDENTIFIER content - owned. */
    unsigned char* policy;
    word32 policySz;
    /* Serial number callback and its data. */
    WOLFSSL_TS_serial_cb serialCb;
    void* serialCbData;
    /* Time callback and its data - when NULL the current time is used. */
    WOLFSSL_TS_time_cb timeCb;
    void* timeCbData;
    /* Accuracy of the time-stamp. */
    int accSecs;
    int accMillis;
    int accMicros;
    /* TS_* flags - e.g. TS_ORDERING. */
    int flags;
};

/* Create a responder context.
 *
 * @return  TS_RESP_CTX object on success.
 * @return  NULL on allocation failure.
 */
WOLFSSL_TS_RESP_CTX* wolfSSL_TS_RESP_CTX_new(void)
{
    WOLFSSL_TS_RESP_CTX* ctx;

    WOLFSSL_ENTER("wolfSSL_TS_RESP_CTX_new");

    ctx = (WOLFSSL_TS_RESP_CTX*)XMALLOC(sizeof(WOLFSSL_TS_RESP_CTX), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (ctx != NULL) {
        XMEMSET(ctx, 0, sizeof(WOLFSSL_TS_RESP_CTX));
        /* Default to SHA-256 for the signature. */
        ctx->hashType = WC_HASH_TYPE_SHA256;
    }
    return ctx;
}

/* Dispose of a responder context.
 *
 * @param [in, out] ctx  TS_RESP_CTX object. May be NULL.
 */
void wolfSSL_TS_RESP_CTX_free(WOLFSSL_TS_RESP_CTX* ctx)
{
    if (ctx != NULL) {
        XFREE(ctx->certDer, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(ctx->keyDer, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(ctx->policy, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(ctx, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

/* Set the signer's certificate.
 *
 * The certificate is copied as DER - the caller keeps ownership of signer.
 *
 * @param [in, out] ctx     TS_RESP_CTX object.
 * @param [in]      signer  Signer's certificate.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_TS_RESP_CTX_set_signer_cert(WOLFSSL_TS_RESP_CTX* ctx,
    WOLFSSL_X509* signer)
{
    int derSz;
    unsigned char* der = NULL;

    if ((ctx == NULL) || (signer == NULL))
        return 0;

    /* Encode the certificate to DER. */
    derSz = wolfSSL_i2d_X509(signer, &der);
    if ((derSz <= 0) || (der == NULL))
        return 0;

    XFREE(ctx->certDer, NULL, DYNAMIC_TYPE_OPENSSL);
    ctx->certDer = der;
    ctx->certSz = (word32)derSz;
    return 1;
}

/* Set the signer's private key.
 *
 * The key is copied as DER - the caller keeps ownership of key.
 *
 * @param [in, out] ctx  TS_RESP_CTX object.
 * @param [in]      key  Signer's private key - RSA or ECDSA.
 * @return  1 on success.
 * @return  0 on failure or an unsupported key type.
 */
int wolfSSL_TS_RESP_CTX_set_signer_key(WOLFSSL_TS_RESP_CTX* ctx,
    WOLFSSL_EVP_PKEY* key)
{
    int derSz;
    int baseId;
    unsigned char* der = NULL;
    enum wc_PkType keyType;

    if ((ctx == NULL) || (key == NULL))
        return 0;

    /* Map the key type to the signature algorithm. */
    baseId = wolfSSL_EVP_PKEY_base_id(key);
    if (baseId == WC_EVP_PKEY_RSA) {
        keyType = WC_PK_TYPE_RSA;
    }
#ifdef HAVE_ECC
    else if (baseId == WC_EVP_PKEY_EC) {
        keyType = WC_PK_TYPE_ECDSA_SIGN;
    }
#endif
    else {
        WOLFSSL_MSG("TS signer key type not supported");
        return 0;
    }

    /* Encode the private key to DER. */
    derSz = wolfSSL_i2d_PrivateKey(key, &der);
    if ((derSz <= 0) || (der == NULL))
        return 0;

    XFREE(ctx->keyDer, NULL, DYNAMIC_TYPE_OPENSSL);
    ctx->keyDer = der;
    ctx->keySz = (word32)derSz;
    ctx->keyType = keyType;
    return 1;
}

/* Set the message digest used for the signature.
 *
 * @param [in, out] ctx  TS_RESP_CTX object.
 * @param [in]      md   Message digest.
 * @return  1 on success.
 * @return  0 on failure or an unsupported digest.
 */
int wolfSSL_TS_RESP_CTX_set_signer_digest(WOLFSSL_TS_RESP_CTX* ctx,
    const WOLFSSL_EVP_MD* md)
{
    int hashType = 0;
    int hashSz = 0;

    if ((ctx == NULL) || (md == NULL))
        return 0;
    if (wolfSSL_EVP_get_hashinfo(md, &hashType, &hashSz) != WOLFSSL_SUCCESS)
        return 0;

    ctx->hashType = (enum wc_HashType)hashType;
    return 1;
}

/* Set the default TSA policy.
 *
 * @param [in, out] ctx     TS_RESP_CTX object.
 * @param [in]      policy  Policy as an OBJECT IDENTIFIER.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_TS_RESP_CTX_set_def_policy(WOLFSSL_TS_RESP_CTX* ctx,
    const WOLFSSL_ASN1_OBJECT* policy)
{
    const unsigned char* oid;
    word32 oidSz;
    word32 idx = 1;
    int len = 0;
    unsigned char* copy;

    if ((ctx == NULL) || (policy == NULL) || (policy->obj == NULL))
        return 0;

    /* The object may be full DER or bare content - store the content. */
    oid = policy->obj;
    oidSz = policy->objSz;
    if ((oidSz >= 2) && (oid[0] == ASN_OBJECT_ID) &&
            (GetLength(oid, &idx, &len, oidSz) >= 0) &&
            (idx + (word32)len == oidSz)) {
        oid += idx;
        oidSz = (word32)len;
    }
    if ((oidSz == 0) || (oidSz > MAX_OID_SZ))
        return 0;

    copy = (unsigned char*)XMALLOC(oidSz, NULL, DYNAMIC_TYPE_OPENSSL);
    if (copy == NULL)
        return 0;
    XMEMCPY(copy, oid, oidSz);

    XFREE(ctx->policy, NULL, DYNAMIC_TYPE_OPENSSL);
    ctx->policy = copy;
    ctx->policySz = oidSz;
    return 1;
}

/* Set the callback that supplies a serial number for each response.
 *
 * @param [in, out] ctx   TS_RESP_CTX object.
 * @param [in]      cb    Serial number callback.
 * @param [in]      data  Data passed to the callback.
 * @return  1 on success.
 * @return  0 when ctx is NULL.
 */
int wolfSSL_TS_RESP_CTX_set_serial_cb(WOLFSSL_TS_RESP_CTX* ctx,
    WOLFSSL_TS_serial_cb cb, void* data)
{
    if (ctx == NULL)
        return 0;
    ctx->serialCb = cb;
    ctx->serialCbData = data;
    return 1;
}

/* Set the callback that supplies the time for each response.
 *
 * @param [in, out] ctx   TS_RESP_CTX object.
 * @param [in]      cb    Time callback.
 * @param [in]      data  Data passed to the callback.
 * @return  1 on success.
 * @return  0 when ctx is NULL.
 */
int wolfSSL_TS_RESP_CTX_set_time_cb(WOLFSSL_TS_RESP_CTX* ctx,
    WOLFSSL_TS_time_cb cb, void* data)
{
    if (ctx == NULL)
        return 0;
    ctx->timeCb = cb;
    ctx->timeCbData = data;
    return 1;
}

/* Set the accuracy of the time-stamp.
 *
 * @param [in, out] ctx     TS_RESP_CTX object.
 * @param [in]      secs    Accuracy in seconds.
 * @param [in]      millis  Accuracy in milliseconds - 0..999.
 * @param [in]      micros  Accuracy in microseconds - 0..999.
 * @return  1 on success.
 * @return  0 when ctx is NULL.
 */
int wolfSSL_TS_RESP_CTX_set_accuracy(WOLFSSL_TS_RESP_CTX* ctx, int secs,
    int millis, int micros)
{
    if (ctx == NULL)
        return 0;
    ctx->accSecs = secs;
    ctx->accMillis = millis;
    ctx->accMicros = micros;
    return 1;
}

/* Add flags to the responder context.
 *
 * @param [in, out] ctx    TS_RESP_CTX object.
 * @param [in]      flags  TS_* flags to add.
 * @return  1 on success.
 * @return  0 when ctx is NULL.
 */
int wolfSSL_TS_RESP_CTX_add_flags(WOLFSSL_TS_RESP_CTX* ctx, int flags)
{
    if (ctx == NULL)
        return 0;
    ctx->flags |= flags;
    return 1;
}

/* Maximum size of a TS request read from the BIO. */
#define TSP_RESP_REQ_DER_SZ 2048

/* Create a time-stamp response for a request.
 *
 * Reads the DER request from the BIO, builds a granted TSTInfo from the
 * request and the context's configured values, signs it into a time-stamp
 * token and returns the response. The signer's certificate is included in the
 * token. A serial number callback must be set; a time callback is optional -
 * the current time is used when not set.
 *
 * @param [in] ctx      TS_RESP_CTX object.
 * @param [in] req_bio  BIO holding the DER encoded TimeStampReq.
 * @return  TS_RESP object on success - free with TS_RESP_free().
 * @return  NULL on failure.
 */
WOLFSSL_TS_RESP* wolfSSL_TS_RESP_create_response(WOLFSSL_TS_RESP_CTX* ctx,
    WOLFSSL_BIO* req_bio)
{
    int ok = 0;
    int n;
    int rngInit = 0;
    word32 reqSz = 0;
    WC_RNG rng;
    TspRequest req;
    TspTstInfo tst;
    TspResponse resp;
    WOLFSSL_TS_RESP* tsResp = NULL;
    WOLFSSL_ASN1_INTEGER* serialInt = NULL;
    const unsigned char* serial = NULL;
    word32 serialSz = 0;
#ifndef NO_ASN_TIME
    byte genTime[ASN_GENERALIZED_TIME_SIZE];
#endif
    const byte* genTimePtr = NULL;
    word32 genTimeSz = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* reqDer = NULL;
#else
    byte reqDer[TSP_RESP_REQ_DER_SZ];
#endif
    byte* token = NULL;
    word32 tokenSz = 0;
    const unsigned char* p;

    WOLFSSL_ENTER("wolfSSL_TS_RESP_create_response");

    /* The signer, key, policy and a serial callback are required. */
    if ((ctx == NULL) || (req_bio == NULL) || (ctx->certDer == NULL) ||
            (ctx->keyDer == NULL) || (ctx->policy == NULL) ||
            (ctx->serialCb == NULL)) {
        WOLFSSL_MSG("TS_RESP_CTX is not fully configured");
        return NULL;
    }

#ifdef WOLFSSL_SMALL_STACK
    reqDer = (byte*)XMALLOC(TSP_RESP_REQ_DER_SZ, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (reqDer == NULL)
        return NULL;
#endif

    /* Read the DER request from the BIO. */
    n = wolfSSL_BIO_read(req_bio, reqDer, TSP_RESP_REQ_DER_SZ);
    if (n <= 0) {
        WOLFSSL_MSG("Failed to read TS request from BIO");
        goto cleanup;
    }
    reqSz = (word32)n;

    /* Decode the request and start a TSTInfo. */
    if ((wc_TspRequest_Decode(&req, reqDer, reqSz) != 0) ||
            (wc_TspTstInfo_Init(&tst) != 0)) {
        goto cleanup;
    }

    /* Get a serial number from the callback - a non-negative INTEGER whose
     * magnitude bytes are the serial number. */
    serialInt = ctx->serialCb(ctx, ctx->serialCbData);
    if (ts_asn1_integer_get(serialInt, &serial, &serialSz) != 1)
        goto cleanup;
    /* ts_asn1_integer_get returns the raw INTEGER content, which keeps the
     * leading 0x00 pad of a positive value whose top byte has the high bit
     * set. wc_TspTstInfo_SetFromRequest strips it before encoding. */

    /* Get the time from the callback. Without time support (NO_ASN_TIME) the
     * callback's time cannot be formatted as a GeneralizedTime, and the
     * encoder cannot supply the current time either, so a response cannot be
     * created - see the genTime encode path which returns an error. */
#ifndef NO_ASN_TIME
    if (ctx->timeCb != NULL) {
        long sec = 0;
        long usec = 0;

        if (ctx->timeCb(ctx, ctx->timeCbData, &sec, &usec) != 1)
            goto cleanup;
        if (wc_TspTstInfo_SetGenTimeAsTime(&tst, (time_t)sec, genTime,
                (word32)sizeof(genTime)) != 0) {
            goto cleanup;
        }
        genTimePtr = genTime;
        genTimeSz = tst.genTimeSz;
    }
#endif

    /* Set the TSTInfo from the request and the configured values. The genTime
     * is NULL when no time callback - the encoder uses the current time. */
    if (wc_TspTstInfo_SetFromRequest(&tst, &req, ctx->policy, ctx->policySz,
            serial, serialSz, genTimePtr, genTimeSz) != 0) {
        goto cleanup;
    }
    /* Apply accuracy and ordering from the context. */
    if ((ctx->accSecs != 0) || (ctx->accMillis != 0) ||
            (ctx->accMicros != 0)) {
        (void)wc_TspTstInfo_SetAccuracy(&tst, (word32)ctx->accSecs,
            (word16)ctx->accMillis, (word16)ctx->accMicros);
    }
    if (ctx->flags & WOLFSSL_TS_ORDERING) {
        tst.ordering = 1;
    }

    /* Sign the TSTInfo into a token - includes the signer's certificate. */
    if (wc_InitRng(&rng) != 0)
        goto cleanup;
    rngInit = 1;
    tokenSz = ctx->certSz + 2048;
    token = (byte*)XMALLOC(tokenSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (token == NULL)
        goto cleanup;
    if (wc_TspTstInfo_Sign(&tst, ctx->certDer, ctx->certSz, ctx->keyDer,
            ctx->keySz, ctx->keyType, ctx->hashType, &rng, token,
            &tokenSz) != 0) {
        goto cleanup;
    }

    /* Wrap the token in a granted response, encode it and load it into a
     * TS_RESP so the getters work. */
    if (wc_TspResponse_Init(&resp) != 0)
        goto cleanup;
    resp.status = WC_TSP_PKISTATUS_GRANTED;
    resp.token = token;
    resp.tokenSz = tokenSz;
    {
        byte* respDer;
        word32 respDerSz = 0;

        /* Get the encoded length, allocate and encode. */
        if (wc_TspResponse_Encode(&resp, NULL, &respDerSz) != 0)
            goto cleanup;
        respDer = (byte*)XMALLOC(respDerSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (respDer == NULL)
            goto cleanup;
        if (wc_TspResponse_Encode(&resp, respDer, &respDerSz) == 0) {
            p = respDer;
            tsResp = wolfSSL_d2i_TS_RESP(NULL, &p, (long)respDerSz);
            if (tsResp != NULL)
                ok = 1;
        }
        XFREE(respDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

cleanup:
    if (!ok) {
        wolfSSL_TS_RESP_free(tsResp);
        tsResp = NULL;
    }
    if (rngInit)
        wc_FreeRng(&rng);
    XFREE(token, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(reqDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    wolfSSL_ASN1_INTEGER_free(serialInt);
    WOLFSSL_LEAVE("wolfSSL_TS_RESP_create_response", ok);
    return tsResp;
}
#endif /* WOLFSSL_TSP_RESPONDER */

#endif /* OPENSSL_EXTRA && WOLFSSL_TSP && HAVE_PKCS7 */

#endif /* WOLFSSL_SSL_TSP_INCLUDED */
