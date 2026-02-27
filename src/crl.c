/* crl.c
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

/*
CRL Options:
 * CRL_STATIC_REVOKED_LIST:                                        default: off
 *                         Enables fixed static list of RevokedCerts to allow
 *                         for a binary search.
 * CRL_MAX_REVOKED_CERTS:                                          default: 4
 *                         Specifies the number of buffers to hold RevokedCerts.
 *                         The default value is set to 4.
 * CRL_REPORT_LOAD_ERRORS:                                         default: off
 *                         Return any errors encountered during loading CRL
 *                         from a directory.
*/

#ifndef WOLFCRYPT_ONLY
#ifdef HAVE_CRL

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#if defined(OPENSSL_EXTRA)
#include <wolfssl/openssl/x509v3.h>
#endif

#ifndef NO_STRING_H
    #include <string.h>
#endif

#ifdef HAVE_CRL_MONITOR
    #if defined(__MACH__) || defined(__FreeBSD__) || defined(__linux__) || \
         defined(_MSC_VER)
        static int StopMonitor(wolfSSL_CRL_mfd_t mfd);
    #else
        #error "CRL monitor only currently supported on linux or mach or windows"
    #endif
#endif /* HAVE_CRL_MONITOR */


/* Initialize CRL members */
int InitCRL(WOLFSSL_CRL* crl, WOLFSSL_CERT_MANAGER* cm)
{
    WOLFSSL_ENTER("InitCRL");
    if(cm != NULL)
        crl->heap = cm->heap;
    else
        crl->heap = NULL;
    crl->cm = cm;
    crl->crlList  = NULL;
    crl->currentEntry = NULL;
#ifdef HAVE_CRL_MONITOR
    crl->monitors[0].path = NULL;
    crl->monitors[1].path = NULL;
    crl->tid = INVALID_THREAD_VAL;
    crl->mfd = WOLFSSL_CRL_MFD_INIT_VAL;
    crl->setup = 0; /* thread setup done predicate */
    if (wolfSSL_CondInit(&crl->cond) != 0) {
        WOLFSSL_MSG("thread condition init failed");
        return BAD_COND_E;
    }
#endif
#ifdef HAVE_CRL_IO
    crl->crlIOCb = NULL;
#endif
    if (wc_InitRwLock(&crl->crlLock) != 0) {
        WOLFSSL_MSG("Init Mutex failed");
        return BAD_MUTEX_E;
    }
#ifdef OPENSSL_ALL
    {
        int ret;
        wolfSSL_RefInit(&crl->ref, &ret);
        (void)ret;
    }
#endif
#if defined(OPENSSL_EXTRA)
    crl->revokedStack = NULL;
#endif

    return 0;
}


#ifdef CRL_STATIC_REVOKED_LIST
/* Compare two RevokedCert entries by (serialSz, serialNumber) for sorting.
 * Returns < 0, 0, or > 0 like memcmp. */
static int CompareRevokedCert(const RevokedCert* a, const RevokedCert* b)
{
    if (a->serialSz != b->serialSz)
        return a->serialSz - b->serialSz;
    return XMEMCMP(a->serialNumber, b->serialNumber, (size_t)a->serialSz);
}

/* Sort revoked cert array in-place using insertion sort. The array is bounded
 * by CRL_MAX_REVOKED_CERTS so O(n^2) is fine. */
static void SortCRL_CertList(RevokedCert* certs, int totalCerts)
{
    int i, j;
    RevokedCert tmp;

    for (i = 1; i < totalCerts; i++) {
        XMEMCPY(&tmp, &certs[i], sizeof(RevokedCert));
        j = i - 1;
        while (j >= 0 && CompareRevokedCert(&certs[j], &tmp) > 0) {
            XMEMCPY(&certs[j + 1], &certs[j], sizeof(RevokedCert));
            j--;
        }
        XMEMCPY(&certs[j + 1], &tmp, sizeof(RevokedCert));
    }
}
#endif /* CRL_STATIC_REVOKED_LIST */

/* Initialize CRL Entry */
static int InitCRL_Entry(CRL_Entry* crle, DecodedCRL* dcrl, const byte* buff,
                         int verified, void* heap)
{
    WOLFSSL_ENTER("InitCRL_Entry");

    XMEMCPY(crle->issuerHash, dcrl->issuerHash, CRL_DIGEST_SIZE);
    /* XMEMCPY(crle->crlHash, dcrl->crlHash, CRL_DIGEST_SIZE);
     * copy the hash here if needed for optimized comparisons */
    XMEMCPY(crle->lastDate, dcrl->lastDate, MAX_DATE_SIZE);
    XMEMCPY(crle->nextDate, dcrl->nextDate, MAX_DATE_SIZE);
    crle->lastDateFormat = dcrl->lastDateFormat;
    crle->nextDateFormat = dcrl->nextDateFormat;
    crle->version = dcrl->version;

#if defined(OPENSSL_EXTRA)
    crle->lastDateAsn1.length = MAX_DATE_SIZE;
    XMEMCPY (crle->lastDateAsn1.data, crle->lastDate,
             (size_t)crle->lastDateAsn1.length);
    crle->lastDateAsn1.type = crle->lastDateFormat;
    crle->nextDateAsn1.length = MAX_DATE_SIZE;
    XMEMCPY (crle->nextDateAsn1.data, crle->nextDate,
             (size_t)crle->nextDateAsn1.length);
    crle->nextDateAsn1.type = crle->nextDateFormat;

    crle->issuer = NULL;
    wolfSSL_d2i_X509_NAME(&crle->issuer, (unsigned char**)&dcrl->issuer,
                          dcrl->issuerSz);
    if (crle->issuer == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }
#endif
#ifdef CRL_STATIC_REVOKED_LIST
    /* ParseCRL_CertList() has already cached the Revoked certs into
       the crle->certs array. Sort it so binary search in
       FindRevokedSerial works correctly. */
    crle->totalCerts = dcrl->totalCerts;
    SortCRL_CertList(crle->certs, crle->totalCerts);
#else
    crle->certs = dcrl->certs;   /* take ownership */
    crle->totalCerts = dcrl->totalCerts;
#endif
    dcrl->certs = NULL;
    crle->crlNumberSet = dcrl->crlNumberSet;
    if (crle->crlNumberSet) {
        XMEMCPY(crle->crlNumber, dcrl->crlNumber, sizeof(crle->crlNumber));
    }
    crle->verified = verified;
    if (!verified) {
        crle->tbsSz = dcrl->sigIndex - dcrl->certBegin;
        crle->signatureSz = dcrl->sigLength;
        crle->signatureOID = dcrl->signatureOID;
        crle->toBeSigned = (byte*)XMALLOC(crle->tbsSz, heap,
                                          DYNAMIC_TYPE_CRL_ENTRY);
        if (crle->toBeSigned == NULL)
            return WOLFSSL_FATAL_ERROR;
        crle->signature = (byte*)XMALLOC(crle->signatureSz, heap,
                                         DYNAMIC_TYPE_CRL_ENTRY);
        if (crle->signature == NULL) {
            XFREE(crle->toBeSigned, heap, DYNAMIC_TYPE_CRL_ENTRY);
            crle->toBeSigned = NULL;
            return WOLFSSL_FATAL_ERROR;
        }

    #ifdef WC_RSA_PSS
        crle->sigParamsSz = dcrl->sigParamsLength;
        if (dcrl->sigParamsLength > 0) {
            crle->sigParams = (byte*)XMALLOC(crle->sigParamsSz, heap,
                                             DYNAMIC_TYPE_CRL_ENTRY);
            if (crle->sigParams== NULL) {
                XFREE(crle->toBeSigned, heap, DYNAMIC_TYPE_CRL_ENTRY);
                crle->toBeSigned = NULL;
                XFREE(crle->signature, heap, DYNAMIC_TYPE_CRL_ENTRY);
                crle->signature = NULL;
                return WOLFSSL_FATAL_ERROR;
            }
            XMEMCPY(crle->sigParams, buff + dcrl->sigParamsIndex,
                crle->sigParamsSz);
        }
    #endif
        XMEMCPY(crle->toBeSigned, buff + dcrl->certBegin, crle->tbsSz);
        XMEMCPY(crle->signature, dcrl->signature, crle->signatureSz);
    #ifndef NO_SKID
        crle->extAuthKeyIdSet = dcrl->extAuthKeyIdSet;
        if (crle->extAuthKeyIdSet)
            XMEMCPY(crle->extAuthKeyId, dcrl->extAuthKeyId, KEYID_SIZE);
    #endif
    }
    else {
        crle->toBeSigned = NULL;
        crle->signature = NULL;
    }

    (void)verified;
    (void)heap;

    return 0;
}

static CRL_Entry* CRL_Entry_new(void* heap)
{
    CRL_Entry* crle = (CRL_Entry*)XMALLOC(sizeof(CRL_Entry), heap,
                                          DYNAMIC_TYPE_CRL_ENTRY);
    if (crle != NULL) {
        XMEMSET(crle, 0, sizeof(CRL_Entry));
        if (wc_InitMutex(&crle->verifyMutex) != 0) {
            XFREE(crle, heap, DYNAMIC_TYPE_CRL_ENTRY);
            crle = NULL;
        }
    }
    (void)heap;
    return crle;
}

/* Free all CRL Entry resources */
static void CRL_Entry_free(CRL_Entry* crle, void* heap)
{
    WOLFSSL_ENTER("CRL_Entry_free");
    if (crle == NULL) {
        WOLFSSL_MSG("CRL Entry is null");
        return;
    }
#ifdef CRL_STATIC_REVOKED_LIST
#if defined(OPENSSL_EXTRA)
    {
        int i;
        for (i = 0; i < CRL_MAX_REVOKED_CERTS; i++) {
            XFREE(crle->certs[i].extensions, heap, DYNAMIC_TYPE_REVOKED);
        }
    }
#endif
    XMEMSET(crle->certs, 0, CRL_MAX_REVOKED_CERTS*sizeof(RevokedCert));
#else
    {
        RevokedCert* tmp;
        RevokedCert* next;

        for (tmp = crle->certs; tmp != NULL; tmp = next) {
            next = tmp->next;
#if defined(OPENSSL_EXTRA)
            XFREE(tmp->extensions, heap, DYNAMIC_TYPE_REVOKED);
#endif
            XFREE(tmp, heap, DYNAMIC_TYPE_REVOKED);
        }

    }
#endif
    XFREE(crle->signature, heap, DYNAMIC_TYPE_CRL_ENTRY);
    XFREE(crle->toBeSigned, heap, DYNAMIC_TYPE_CRL_ENTRY);
#ifdef WC_RSA_PSS
    XFREE(crle->sigParams, heap, DYNAMIC_TYPE_CRL_ENTRY);
#endif
#if defined(OPENSSL_EXTRA)
    if (crle->issuer != NULL) {
        FreeX509Name(crle->issuer);
        XFREE(crle->issuer, heap, DYNAMIC_TYPE_X509);
    }
#endif
    wc_FreeMutex(&crle->verifyMutex);
    XFREE(crle, heap, DYNAMIC_TYPE_CRL_ENTRY);
    (void)heap;
}


/* Free all CRL resources */
void FreeCRL(WOLFSSL_CRL* crl, int dynamic)
{
    CRL_Entry* tmp;

    WOLFSSL_ENTER("FreeCRL");

    if (crl == NULL)
        return;

#ifdef OPENSSL_ALL
    {
        int ret;
        int doFree = 0;
        wolfSSL_RefDec(&crl->ref, &doFree, &ret);
        if (ret != 0)
            WOLFSSL_MSG("Couldn't lock x509 mutex");
        if (!doFree)
            return;
        wolfSSL_RefFree(&crl->ref);
    }
#endif

    tmp = crl->crlList;
#ifdef HAVE_CRL_MONITOR
    if (crl->monitors[0].path)
        XFREE(crl->monitors[0].path, crl->heap, DYNAMIC_TYPE_CRL_MONITOR);

    if (crl->monitors[1].path)
        XFREE(crl->monitors[1].path, crl->heap, DYNAMIC_TYPE_CRL_MONITOR);
#endif

#if defined(OPENSSL_EXTRA)
    if (crl->revokedStack != NULL) {
        wolfSSL_sk_pop_free(crl->revokedStack, NULL);
        crl->revokedStack = NULL;
    }
#endif
    XFREE(crl->currentEntry, crl->heap, DYNAMIC_TYPE_CRL_ENTRY);
    crl->currentEntry = NULL;
    while(tmp) {
        CRL_Entry* next = tmp->next;
        CRL_Entry_free(tmp, crl->heap);
        tmp = next;
    }

#ifdef HAVE_CRL_MONITOR
    if (crl->tid != INVALID_THREAD_VAL) {
        WOLFSSL_MSG("stopping monitor thread");
        if (StopMonitor(crl->mfd) == 0) {
            if (wolfSSL_JoinThread(crl->tid) != 0)
                WOLFSSL_MSG("stop monitor failed in wolfSSL_JoinThread");
        }
        else {
            WOLFSSL_MSG("stop monitor failed");
        }
    }
    if (wolfSSL_CondFree(&crl->cond) != 0)
        WOLFSSL_MSG("wolfSSL_CondFree failed in FreeCRL");
#endif
    wc_FreeRwLock(&crl->crlLock);
    if (dynamic)   /* free self */
        XFREE(crl, crl->heap, DYNAMIC_TYPE_CRL);
}

static int FindRevokedSerial(RevokedCert* rc, byte* serial, int serialSz,
        byte* serialHash, int totalCerts)
{
    int ret = 0;
    byte hash[SIGNER_DIGEST_SIZE];
#ifdef CRL_STATIC_REVOKED_LIST
    if (serialHash == NULL) {
        /* Binary search by (serialSz, serialNumber). The array was sorted in
         * InitCRL_Entry by the same comparison key. */
        int low = 0;
        int high = totalCerts - 1;

        while (low <= high) {
            int mid = (low + high) / 2;
            int cmp;

            /* Compare by serial size first, then by serial content. Shorter
             * serials sort before longer ones. */
            if (rc[mid].serialSz != serialSz) {
                cmp = rc[mid].serialSz - serialSz;
            }
            else {
                cmp = XMEMCMP(rc[mid].serialNumber, serial,
                              (size_t)rc[mid].serialSz);
            }

            if (cmp < 0) {
                low = mid + 1;
            }
            else if (cmp > 0) {
                high = mid - 1;
            }
            else {
                WOLFSSL_MSG("Cert revoked");
                ret = CRL_CERT_REVOKED;
                break;
            }
        }
    }
    else {
        /* Hash-based lookup -- linear scan required since the array is sorted
         * by serial number, not by hash. */
        int i;
        for (i = 0; i < totalCerts; i++) {
            ret = CalcHashId(rc[i].serialNumber, (word32)rc[i].serialSz, hash);
            if (ret != 0)
                break;
            if (XMEMCMP(hash, serialHash, SIGNER_DIGEST_SIZE) == 0) {
                WOLFSSL_MSG("Cert revoked");
                ret = CRL_CERT_REVOKED;
                break;
            }
        }
    }
#else
    (void)totalCerts;
    /* search in the linked list*/
    while (rc) {
        if (serialHash == NULL) {
            if (rc->serialSz == serialSz &&
                   XMEMCMP(rc->serialNumber, serial, (size_t)rc->serialSz) == 0) {
                WOLFSSL_MSG("Cert revoked");
                ret = CRL_CERT_REVOKED;
                break;
            }
        }
        else {
            ret = CalcHashId(rc->serialNumber, (word32)rc->serialSz, hash);
            if (ret != 0)
                break;
            if (XMEMCMP(hash, serialHash, SIGNER_DIGEST_SIZE) == 0) {
                WOLFSSL_MSG("Cert revoked");
                ret = CRL_CERT_REVOKED;
                break;
            }
        }
        rc = rc->next;
    }
#endif
    return ret;
}

static int VerifyCRLE(const WOLFSSL_CRL* crl, CRL_Entry* crle)
{
    Signer* ca = NULL;
    SignatureCtx sigCtx;
    int ret = 0;

#ifndef NO_SKID
    if (crle->extAuthKeyIdSet)
        ca = GetCA(crl->cm, crle->extAuthKeyId);
    if (ca == NULL)
        ca = GetCAByName(crl->cm, crle->issuerHash);
#else /* NO_SKID */
    ca = GetCA(crl->cm, crle->issuerHash);
#endif /* NO_SKID */
    if (ca == NULL) {
        WOLFSSL_MSG("Did NOT find CRL issuer CA");
        return ASN_CRL_NO_SIGNER_E;
    }

    ret = VerifyCRL_Signature(&sigCtx, crle->toBeSigned, crle->tbsSz,
            crle->signature, crle->signatureSz, crle->signatureOID,
        #ifdef WC_RSA_PSS
            crle->sigParams, (int)crle->sigParamsSz,
        #else
            NULL, 0,
        #endif
            ca, crl->heap);

    if (ret == 0) {
        crle->verified = 1;
    }
    else {
        crle->verified = ret;
    }

    return ret;
}

static int CheckCertCRLList(WOLFSSL_CRL* crl, byte* issuerHash, byte* serial,
        int serialSz, byte* serialHash, int *pFoundEntry)
{
    CRL_Entry* crle;
    int        foundEntry = 0;
    int        ret = 0;

    if (wc_LockRwLock_Rd(&crl->crlLock) != 0) {
        WOLFSSL_MSG("wc_LockRwLock_Rd failed");
        return BAD_MUTEX_E;
    }

    for (crle = crl->crlList; crle != NULL; crle = crle->next) {
        if (XMEMCMP(crle->issuerHash, issuerHash, CRL_DIGEST_SIZE) == 0) {
            int nextDateValid = 1;

            WOLFSSL_MSG("Found CRL Entry on list");

            if (crle->verified == 0) {
                if (wc_LockMutex(&crle->verifyMutex) != 0) {
                    WOLFSSL_MSG("wc_LockMutex failed");
                    break;
                }

                /* A different thread may have verified the entry while we were
                 * waiting for the mutex. */
                if (crle->verified == 0)
                    ret = VerifyCRLE(crl, crle);

                wc_UnLockMutex(&crle->verifyMutex);

                if (ret != 0)
                    break;
            }

            if (crle->verified < 0) {
                WOLFSSL_MSG("Cannot use CRL as it didn't verify");
                ret = crle->verified;
                break;
            }

            WOLFSSL_MSG("Checking next date validity");

        #ifdef WOLFSSL_NO_CRL_NEXT_DATE
            if (crle->nextDateFormat != ASN_OTHER_TYPE)
        #endif
            {
            #if !defined(NO_ASN_TIME) && !defined(WOLFSSL_NO_CRL_DATE_CHECK)
                if (!XVALIDATE_DATE(crle->nextDate, crle->nextDateFormat,
                                   ASN_AFTER, MAX_DATE_SIZE)) {
                    WOLFSSL_MSG("CRL next date is no longer valid");
                    nextDateValid = 0;
                }
            #endif
            }
            if (nextDateValid) {
                foundEntry = 1;
                ret = FindRevokedSerial(crle->certs, serial, serialSz,
                        serialHash, crle->totalCerts);
                if (ret != 0)
                    break;
            }
            else if (foundEntry == 0) {
                ret = CRL_CERT_DATE_ERR;
            }
        }
    }

    wc_UnLockRwLock(&crl->crlLock);

    *pFoundEntry = foundEntry;

    return ret;
}

int CheckCertCRL_ex(WOLFSSL_CRL* crl, byte* issuerHash, byte* serial,
        int serialSz, byte* serialHash, const byte* extCrlInfo,
        int extCrlInfoSz, void* issuerName)
{
    int        foundEntry = 0;
    int        ret = 0;

    WOLFSSL_ENTER("CheckCertCRL");
    (void)issuerName;

    if ((serial == NULL || serialSz == 0) && serialHash == NULL) {
        WOLFSSL_MSG("Either serial or hash has to be provided");
        return BUFFER_ERROR;
    }

#ifdef WOLFSSL_CRL_ALLOW_MISSING_CDP
    /* Skip CRL verification in case no CDP in peer cert */
    if (!extCrlInfo) {
        return ret;
    }
#endif

    ret = CheckCertCRLList(crl, issuerHash, serial, serialSz, serialHash,
            &foundEntry);

#ifdef HAVE_CRL_IO
    if (foundEntry == 0) {
        /* perform embedded lookup */
        if (crl->crlIOCb) {
            int cbRet = crl->crlIOCb(crl, (const char*)extCrlInfo,
                                     extCrlInfoSz);
            if (cbRet == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_WANT_READ)) {
                ret = OCSP_WANT_READ;
            }
            else if (ret >= 0) {
                /* try again */
                ret = CheckCertCRLList(crl, issuerHash, serial, serialSz,
                        serialHash, &foundEntry);
            }
        }
    }
#endif

#if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN) && \
    (defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_EXT)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR) && \
    !defined(NO_STDIO_FILESYSTEM) && \
    (!defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH))
    /* if not find entry in the CRL list, it looks at the folder that sets  */
    /* by LOOKUP_ctrl because user would want to use hash_dir.              */
    /* Loading <issuer-hash>.rN form CRL file if find at the folder,        */
    /* and try again checking Cert in the CRL list.                         */
    /* When not set the folder or not use hash_dir, do nothing.             */
    if ((foundEntry == 0) && (ret != WC_NO_ERR_TRACE(OCSP_WANT_READ))) {
        if (crl->cm != NULL && crl->cm->x509_store_p != NULL) {
            int loadRet = LoadCertByIssuer(crl->cm->x509_store_p,
                          (WOLFSSL_X509_NAME*)issuerName, X509_LU_CRL);
            if (loadRet == WOLFSSL_SUCCESS) {
                /* try again */
                ret = CheckCertCRLList(crl, issuerHash, serial, serialSz,
                        serialHash, &foundEntry);
            }
        }
    }
#endif
    if (foundEntry == 0) {
        WOLFSSL_MSG("Couldn't find CRL for status check");
        if (ret != WC_NO_ERR_TRACE(CRL_CERT_DATE_ERR)) {
            ret = CRL_MISSING;
        }

        if (crl->cm != NULL && crl->cm->cbMissingCRL) {
            char url[256];

            WOLFSSL_MSG("Issuing missing CRL callback");
            url[0] = '\0';
            if (extCrlInfo) {
                if (extCrlInfoSz < (int)sizeof(url) -1 ) {
                    XMEMCPY(url, extCrlInfo, (size_t)extCrlInfoSz);
                    url[extCrlInfoSz] = '\0';
                }
                else  {
                    WOLFSSL_MSG("CRL url too long");
                }
            }

            crl->cm->cbMissingCRL(url);
        }

        if (crl->cm != NULL && crl->cm->crlCb &&
                crl->cm->crlCb(ret, crl, crl->cm, crl->cm->crlCbCtx)) {
            if (ret != 0)
                WOLFSSL_MSG("Overriding CRL error");
            ret = 0;
        }
    }

    return ret;
}

/* Is the cert ok with CRL, return 0 on success */
int CheckCertCRL(WOLFSSL_CRL* crl, DecodedCert* cert)
{
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    void* issuerName = cert->issuerName;
#else
    void* issuerName = NULL;
#endif
    return CheckCertCRL_ex(crl, cert->issuerHash, cert->serial, cert->serialSz,
            NULL, cert->extCrlInfo, cert->extCrlInfoSz, issuerName);
}

#ifdef HAVE_CRL_UPDATE_CB
static void SetCrlInfo(CRL_Entry* entry, CrlInfo *info)
{
    info->issuerHash = (byte *)entry->issuerHash;
    info->issuerHashLen = CRL_DIGEST_SIZE;
    info->lastDate = (byte *)entry->lastDate;
    info->lastDateMaxLen = MAX_DATE_SIZE;
    info->lastDateFormat = entry->lastDateFormat;
    info->nextDate = (byte *)entry->nextDate;
    info->nextDateMaxLen = MAX_DATE_SIZE;
    info->nextDateFormat = entry->nextDateFormat;
    info->crlNumberSet = entry->crlNumberSet;
    if (info->crlNumberSet)
        XMEMCPY(info->crlNumber, entry->crlNumber, sizeof(entry->crlNumber));
}

static void SetCrlInfoFromDecoded(DecodedCRL* entry, CrlInfo *info)
{
    info->issuerHash = (byte *)entry->issuerHash;
    info->issuerHashLen = SIGNER_DIGEST_SIZE;
    info->lastDate = (byte *)entry->lastDate;
    info->lastDateMaxLen = MAX_DATE_SIZE;
    info->lastDateFormat = entry->lastDateFormat;
    info->nextDate = (byte *)entry->nextDate;
    info->nextDateMaxLen = MAX_DATE_SIZE;
    info->nextDateFormat = entry->nextDateFormat;
    info->crlNumberSet = entry->crlNumberSet;
    if (info->crlNumberSet)
        XMEMCPY(info->crlNumber, entry->crlNumber, sizeof(entry->crlNumber));
}
#endif

/* Returns MP_GT if prev crlNumber is smaller
 *         MP_EQ if equal
 *         MP_LT if prev crlNumber is larger */
static int CompareCRLnumber(CRL_Entry* prev, CRL_Entry* curr)
{
    int ret = 0;
    DECL_MP_INT_SIZE_DYN(prev_num, CRL_MAX_NUM_SZ_BITS,
                                   CRL_MAX_NUM_SZ_BITS);
    DECL_MP_INT_SIZE_DYN(curr_num, CRL_MAX_NUM_SZ_BITS,
                                   CRL_MAX_NUM_SZ_BITS);

    NEW_MP_INT_SIZE(prev_num, CRL_MAX_NUM_SZ_BITS, NULL,
                                   DYNAMIC_TYPE_TMP_BUFFER);
    NEW_MP_INT_SIZE(curr_num, CRL_MAX_NUM_SZ_BITS, NULL,
                                   DYNAMIC_TYPE_TMP_BUFFER);
#ifdef MP_INT_SIZE_CHECK_NULL
    if ((prev_num == NULL) || (curr_num == NULL)) {
        ret = MEMORY_E;
    }
#endif

    if (ret == 0 && ((INIT_MP_INT_SIZE(prev_num, CRL_MAX_NUM_SZ_BITS)
                != MP_OKAY) || (INIT_MP_INT_SIZE(curr_num,
                CRL_MAX_NUM_SZ_BITS)) != MP_OKAY)) {
        ret = MP_INIT_E;
    }

    if (ret == 0 && (mp_read_radix(prev_num, (char*)prev->crlNumber,
                MP_RADIX_HEX) != MP_OKAY ||
                mp_read_radix(curr_num, (char*)curr->crlNumber,
                MP_RADIX_HEX) != MP_OKAY)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0)
        ret = mp_cmp(prev_num, curr_num);

    FREE_MP_INT_SIZE(prev_num, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    FREE_MP_INT_SIZE(curr_num, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* Add or replace a decoded CRL, 0 on success */
static int AddCRL(WOLFSSL_CRL* crl, DecodedCRL* dcrl, CRL_Entry* crle,
                  const byte* buff, int verified)
{
    CRL_Entry* curr = NULL;
    CRL_Entry* prev = NULL;
#ifdef HAVE_CRL_UPDATE_CB
    CrlInfo old;
    CrlInfo cnew;
#endif
    int ret = 0;

    WOLFSSL_ENTER("AddCRL");

    if (crl == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (InitCRL_Entry(crle, dcrl, buff, verified, crl->heap) < 0) {
        WOLFSSL_MSG("Init CRL Entry failed");
        return WOLFSSL_FATAL_ERROR;
    }

    if (wc_LockRwLock_Wr(&crl->crlLock) != 0) {
        WOLFSSL_MSG("wc_LockRwLock_Wr failed");
        return BAD_MUTEX_E;
    }

    for (curr = crl->crlList; curr != NULL; curr = curr->next) {
        if (XMEMCMP(curr->issuerHash, crle->issuerHash, CRL_DIGEST_SIZE) == 0) {
            ret = CompareCRLnumber(crle, curr);
            /* Error out if the CRL we're attempting to add isn't more
             * authoritative than the existing entry */
            if (ret == MP_LT || ret == MP_EQ) {
                WOLFSSL_MSG("Same or newer CRL entry already exists");
                wc_UnLockRwLock(&crl->crlLock);
                return DUPE_ENTRY_E;
            }
            else if (ret < 0) {
                WOLFSSL_MSG("Error comparing CRL Numbers");
                wc_UnLockRwLock(&crl->crlLock);
                return ret;
            }

            /* Insert the new entry after the current entry. */
            crle->next = curr->next;
            if (prev != NULL) {
                prev->next = crle;
            }
            else {
                crl->crlList = crle;
            }

#ifdef HAVE_CRL_UPDATE_CB
            if (crl->cm && crl->cm->cbUpdateCRL != NULL) {
                SetCrlInfo(curr, &old);
                SetCrlInfo(crle, &cnew);
                crl->cm->cbUpdateCRL(&old, &cnew);
            }
#endif

            /* Remove the current entry which was replaced */
            CRL_Entry_free(curr, crl->heap);

            break;
        }
        prev = curr;
    }

    if (curr == NULL) {
        /* No replacement occurred, prepend the new entry. */
        crle->next = crl->crlList;
        crl->crlList = crle;
    }

    wc_UnLockRwLock(&crl->crlLock);
    return 0;
}


/* Load CRL File of type, WOLFSSL_SUCCESS on ok */
int BufferLoadCRL(WOLFSSL_CRL* crl, const byte* buff, long sz, int type,
                  int verify)
{
    int          ret = WOLFSSL_SUCCESS;
    const byte*  myBuffer = buff;    /* if DER ok, otherwise switch */
    DerBuffer*   der = NULL;
    WC_DECLARE_VAR(dcrl, DecodedCRL, 1, 0);

    WOLFSSL_ENTER("BufferLoadCRL");

    if (crl == NULL || buff == NULL || sz == 0)
        return BAD_FUNC_ARG;

    if (type == WOLFSSL_FILETYPE_PEM) {
    #ifdef WOLFSSL_PEM_TO_DER
        ret = PemToDer(buff, sz, CRL_TYPE, &der, NULL, NULL, NULL);
        if (ret == 0) {
            myBuffer = der->buffer;
            sz = der->length;
        }
        else {
            WOLFSSL_MSG("Pem to Der failed");
            FreeDer(&der);
            return WOLFSSL_FATAL_ERROR;
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }

#ifdef WOLFSSL_SMALL_STACK
    dcrl = (DecodedCRL*)XMALLOC(sizeof(DecodedCRL), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (dcrl == NULL) {
        FreeDer(&der);
        return MEMORY_E;
    }
#endif

    crl->currentEntry = CRL_Entry_new(crl->heap);
    if (crl->currentEntry == NULL) {
        WOLFSSL_MSG_CERT_LOG("alloc CRL Entry failed");
        WC_FREE_VAR_EX(dcrl, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        FreeDer(&der);
        return MEMORY_E;
    }

    InitDecodedCRL(dcrl, crl->heap);
    ret = ParseCRL(crl->currentEntry->certs, dcrl, myBuffer, (word32)sz,
                   verify, crl->cm);

    if (ret != 0 && !(ret == WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E)
                      && verify == NO_VERIFY)) {
        WOLFSSL_MSG_CERT_LOG("ParseCRL error");
        WOLFSSL_MSG_CERT_EX("ParseCRL verify = %d, ret = %d", verify, ret);
        CRL_Entry_free(crl->currentEntry, crl->heap);
        crl->currentEntry = NULL;
    }
    else {
        ret = AddCRL(crl, dcrl, crl->currentEntry, myBuffer,
                     ret != WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E));
        if (ret != 0) {
            WOLFSSL_MSG_CERT_LOG("AddCRL error");
            CRL_Entry_free(crl->currentEntry, crl->heap);
        }
        /* Entry now is in the list, or has been freed due to error */
        crl->currentEntry = NULL;
    }

    FreeDecodedCRL(dcrl);

    WC_FREE_VAR_EX(dcrl, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    FreeDer(&der);

    return ret ? ret : WOLFSSL_SUCCESS; /* convert 0 to WOLFSSL_SUCCESS */
}

/* Store CRL into a buffer in DER or PEM format.
 * If buff is NULL, updates inOutSz with required size and returns success.
 * Returns WOLFSSL_SUCCESS on success, negative on failure.
 */
int BufferStoreCRL(WOLFSSL_CRL* crl, byte* buff, long* inOutSz, int type)
{
    int ret = 0;
    CRL_Entry* ent = NULL;
    const byte* tbs = NULL;
    word32 tbsSz = 0;
    const byte* sig = NULL;
    word32 sigSz = 0;
    word32 sigOID = 0;
#ifdef WC_RSA_PSS
    const byte* sigParams = NULL;
    word32 sigParamsSz = 0;
#endif
    word32 algoLen = 0;
    word32 bitHdrLen = 0;
    word32 totalContentLen = 0;
    word32 outerHdrLen = 0;
    word32 derNeeded = 0;
    long outSz = 0;

    WOLFSSL_ENTER("BufferStoreCRL");

    if (crl == NULL || inOutSz == NULL) {
        return BAD_FUNC_ARG;
    }

    outSz = *inOutSz;

    /* Access the first CRL entry. Lock is held until encoding is complete
     * to prevent the entry from being freed by another thread. */
    if (wc_LockRwLock_Rd(&crl->crlLock) != 0) {
        WOLFSSL_MSG("wc_LockRwLock_Rd failed");
        return BAD_MUTEX_E;
    }
    ent = crl->crlList;
    if (ent != NULL) {
        tbs = ent->toBeSigned;
        tbsSz = ent->tbsSz;
        sig = ent->signature;
        sigSz = ent->signatureSz;
        sigOID = ent->signatureOID;
#ifdef WC_RSA_PSS
        sigParams = ent->sigParams;
        sigParamsSz = ent->sigParamsSz;
#endif
    }

    if (ent == NULL || tbs == NULL || tbsSz == 0 || sig == NULL || sigSz == 0) {
        WOLFSSL_MSG("CRL entry missing toBeSigned/signature data");
        ret = BAD_FUNC_ARG;
    }

    /* Calculate encoded lengths for AlgorithmIdentifier. */
    if (ret == 0) {
#ifdef WC_RSA_PSS
        if (sigParams != NULL && sigParamsSz > 0) {
            /* OID + explicit parameters inside SEQUENCE */
            word32 oidSz = 0;
            word32 idLen;
            const byte* oid = OidFromId(sigOID, oidSigType, &oidSz);
            if (oid == NULL) {
                WOLFSSL_MSG("Unknown signature OID for CRL");
                ret = WOLFSSL_FATAL_ERROR;
            }
            else {
                /* OBJECT IDENTIFIER header */
                idLen = (word32)SetObjectId((int)oidSz, NULL);
                algoLen = SetSequence(idLen + oidSz + sigParamsSz, NULL)
                        + idLen + oidSz + sigParamsSz;
            }
        }
        else
#endif
        {
            algoLen = SetAlgoID((int)sigOID, NULL, oidSigType, 0);
            if (algoLen == 0) {
                WOLFSSL_MSG("SetAlgoID failed");
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
    }

    if (ret == 0) {
        /* BIT STRING header for signature */
        bitHdrLen = SetBitString(sigSz, 0, NULL);

        /* Compute total DER size. */
        totalContentLen = tbsSz + algoLen + bitHdrLen + sigSz;
        outerHdrLen = SetSequence(totalContentLen, NULL);
        derNeeded = outerHdrLen + totalContentLen;
    }

    if (ret == 0 && type == WOLFSSL_FILETYPE_ASN1) {
        if (buff == NULL) {
            *inOutSz = (long)derNeeded;
            ret = WOLFSSL_SUCCESS;
        }
        else if ((long)derNeeded > outSz) {
            WOLFSSL_MSG("Output buffer too small for DER CRL");
            ret = BUFFER_E;
        }
        else {
            /* Encode DER CRL directly into caller buffer. */
            word32 pos = 0;
#ifdef WC_RSA_PSS
            word32 oidSz = 0;
            const byte* oid = NULL;
#endif
            /* Outer SEQUENCE header */
            pos += SetSequence(totalContentLen, buff + pos);
            /* tbsCertList */
            XMEMCPY(buff + pos, tbs, tbsSz);
            pos += tbsSz;

            /* signatureAlgorithm AlgorithmIdentifier */
#ifdef WC_RSA_PSS
            if (sigParams != NULL && sigParamsSz > 0) {
                /* Lookup OID bytes for signature algorithm. */
                oid = OidFromId(sigOID, oidSigType, &oidSz);
                if (oid == NULL) {
                    WOLFSSL_MSG("Unknown signature OID for CRL");
                    ret = WOLFSSL_FATAL_ERROR;
                }
                else {
                    /* SEQUENCE header for AlgorithmIdentifier */
                    pos += SetSequence((word32)SetObjectId((int)oidSz, NULL) +
                                       oidSz + sigParamsSz, buff + pos);
                    /* OBJECT IDENTIFIER header and content */
                    pos += (word32)SetObjectId((int)oidSz, buff + pos);
                    XMEMCPY(buff + pos, oid, oidSz);
                    pos += oidSz;
                    /* Parameters as captured (already DER encoded) */
                    XMEMCPY(buff + pos, sigParams, sigParamsSz);
                    pos += sigParamsSz;
                }
            }
            else
#endif
            {
                pos += SetAlgoID((int)sigOID, buff + pos, oidSigType, 0);
            }

            if (ret == 0) {
                /* signature BIT STRING and bytes */
                pos += SetBitString(sigSz, 0, buff + pos);
                XMEMCPY(buff + pos, sig, sigSz);

                *inOutSz = (long)derNeeded;
                ret = WOLFSSL_SUCCESS;
            }
            (void)pos; /* pos not used after this point */
        }
    }
#ifdef WOLFSSL_DER_TO_PEM
    else if (ret == 0 && type == WOLFSSL_FILETYPE_PEM) {
        byte* derTmp = NULL;
        int pemSz;
        /* Build DER first in a temporary buffer. */
        derTmp = (byte*)XMALLOC(derNeeded, crl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (derTmp == NULL) {
            ret = MEMORY_E;
        }

        if (ret == 0) {
            /* Encode DER CRL into temporary buffer. */
            word32 pos = 0;
#ifdef WC_RSA_PSS
            word32 oidSz = 0;
            const byte* oid = NULL;
#endif
            pos += SetSequence(totalContentLen, derTmp + pos);
            XMEMCPY(derTmp + pos, tbs, tbsSz);
            pos += tbsSz;
#ifdef WC_RSA_PSS
            if (sigParams != NULL && sigParamsSz > 0) {
                oid = OidFromId(sigOID, oidSigType, &oidSz);
                if (oid == NULL) {
                    ret = WOLFSSL_FATAL_ERROR;
                }
                else {
                    pos += SetSequence((word32)SetObjectId((int)oidSz, NULL) +
                                       oidSz + sigParamsSz, derTmp + pos);
                    pos += (word32)SetObjectId((int)oidSz, derTmp + pos);
                    XMEMCPY(derTmp + pos, oid, oidSz);
                    pos += oidSz;
                    XMEMCPY(derTmp + pos, sigParams, sigParamsSz);
                    pos += sigParamsSz;
                }
            }
            else
#endif
            {
                pos += SetAlgoID((int)sigOID, derTmp + pos, oidSigType, 0);
            }
            if (ret == 0) {
                pos += SetBitString(sigSz, 0, derTmp + pos);
                XMEMCPY(derTmp + pos, sig, sigSz);
            }
            (void)pos; /* pos not used after this point */
        }

        /* Determine required PEM size. */
        if (ret == 0) {
            pemSz = wc_DerToPemEx(derTmp, derNeeded, NULL, 0, NULL, CRL_TYPE);
            if (pemSz < 0) {
                ret = WOLFSSL_FATAL_ERROR;
            }
            else if (buff == NULL) {
                *inOutSz = pemSz;
                ret = WOLFSSL_SUCCESS;
            }
            else if (outSz < pemSz) {
                WOLFSSL_MSG("Output buffer too small for PEM CRL");
                ret = BUFFER_E;
            }
            else if (wc_DerToPemEx(derTmp, derNeeded, buff, (word32)pemSz,
                                   NULL, CRL_TYPE) < 0) {
                ret = WOLFSSL_FATAL_ERROR;
            }
            else {
                *inOutSz = pemSz;
                ret = WOLFSSL_SUCCESS;
            }
        }

        XFREE(derTmp, crl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif /* WOLFSSL_DER_TO_PEM */
    else if (ret == 0) {
        ret = BAD_FUNC_ARG;
    }

    wc_UnLockRwLock(&crl->crlLock);
    return ret;
}

#ifdef HAVE_CRL_UPDATE_CB
/* Fill out CRL info structure, WOLFSSL_SUCCESS on ok */
int GetCRLInfo(WOLFSSL_CRL* crl, CrlInfo* info, const byte* buff,
    long sz, int type)
{
    int          ret = WOLFSSL_SUCCESS;
    const byte*  myBuffer = buff;    /* if DER ok, otherwise switch */
    DerBuffer*   der = NULL;
    CRL_Entry*   crle = NULL;
    WC_DECLARE_VAR(dcrl, DecodedCRL, 1, 0);

    WOLFSSL_ENTER("GetCRLInfo");

    if (crl == NULL || info == NULL || buff == NULL || sz == 0)
        return BAD_FUNC_ARG;

    if (type == WOLFSSL_FILETYPE_PEM) {
    #ifdef WOLFSSL_PEM_TO_DER
        ret = PemToDer(buff, sz, CRL_TYPE, &der, NULL, NULL, NULL);
        if (ret == 0) {
            myBuffer = der->buffer;
            sz = der->length;
        }
        else {
            WOLFSSL_MSG("Pem to Der failed");
            FreeDer(&der);
            return -1;
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }

#ifdef WOLFSSL_SMALL_STACK
    dcrl = (DecodedCRL*)XMALLOC(sizeof(DecodedCRL), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (dcrl == NULL) {
        FreeDer(&der);
        return MEMORY_E;
    }
#endif

    crle = CRL_Entry_new(crl->heap);
    if (crle == NULL) {
        WOLFSSL_MSG("alloc CRL Entry failed");
        WC_FREE_VAR_EX(dcrl, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        FreeDer(&der);
        return MEMORY_E;
    }

    InitDecodedCRL(dcrl, crl->heap);
    ret = ParseCRL(crle->certs, dcrl, myBuffer, (word32)sz,
                   0, crl->cm);
    if (ret != 0 && !(ret == WC_NO_ERR_TRACE(ASN_CRL_NO_SIGNER_E))) {
        WOLFSSL_MSG("ParseCRL error");
        CRL_Entry_free(crle, crl->heap);
        crle = NULL;
    }
    else {
        SetCrlInfoFromDecoded((DecodedCRL*)dcrl, info);
    }

    FreeDecodedCRL(dcrl);

    WC_FREE_VAR_EX(dcrl, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    FreeDer(&der);
    CRL_Entry_free(crle, crl->heap);

    return ret ? ret : WOLFSSL_SUCCESS; /* convert 0 to WOLFSSL_SUCCESS */
}
#endif

#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL)
/* helper function to create a new dynamic WOLFSSL_X509_CRL structure */
static WOLFSSL_X509_CRL* wolfSSL_X509_crl_new(WOLFSSL_CERT_MANAGER* cm)
{
    WOLFSSL_X509_CRL* ret;
    void* heap = NULL;

    if (cm != NULL) {
        heap = cm->heap;
    }

    ret = (WOLFSSL_X509_CRL*)XMALLOC(sizeof(WOLFSSL_X509_CRL), heap,
        DYNAMIC_TYPE_CRL);
    if (ret != NULL) {
        if (InitCRL(ret, cm) < 0) {
            WOLFSSL_MSG("Unable to initialize new CRL structure");
            XFREE(ret, heap, DYNAMIC_TYPE_CRL);
            ret = NULL;
        }
    }
    return ret;
}

#ifndef CRL_STATIC_REVOKED_LIST
/* returns head of copied list that was alloc'd */
static RevokedCert *DupRevokedCertList(RevokedCert* in, void* heap)
{
    RevokedCert* head = NULL;
    RevokedCert* current = in;
    RevokedCert* prev = NULL;
    while (current) {
        RevokedCert* tmp = (RevokedCert*)XMALLOC(sizeof(RevokedCert), heap,
                DYNAMIC_TYPE_REVOKED);
        if (tmp != NULL) {
            XMEMCPY(tmp->serialNumber, current->serialNumber,
                    EXTERNAL_SERIAL_SIZE);
            tmp->serialSz = current->serialSz;
            XMEMCPY(tmp->revDate, current->revDate,
                    MAX_DATE_SIZE);
            tmp->revDateFormat = current->revDateFormat;
            tmp->reasonCode = current->reasonCode;
#if defined(OPENSSL_EXTRA)
            tmp->extensions = NULL;
            tmp->extensionsSz = 0;
            if (current->extensions != NULL && current->extensionsSz > 0) {
                tmp->extensions = (byte*)XMALLOC(current->extensionsSz, heap,
                                                 DYNAMIC_TYPE_REVOKED);
                if (tmp->extensions != NULL) {
                    XMEMCPY(tmp->extensions, current->extensions,
                            current->extensionsSz);
                    tmp->extensionsSz = current->extensionsSz;
                }
            }
#endif
            tmp->next = NULL;
            if (prev != NULL)
                prev->next = tmp;
            if (head == NULL)
                head = tmp;
            prev = tmp;
        }
        else {
            WOLFSSL_MSG("Failed to allocate new RevokedCert structure");
            /* free up any existing list */
            while (head != NULL) {
                current = head;
                head = head->next;
#if defined(OPENSSL_EXTRA)
                XFREE(current->extensions, heap, DYNAMIC_TYPE_REVOKED);
#endif
                XFREE(current, heap, DYNAMIC_TYPE_REVOKED);
            }
            return NULL;
        }
        current = current->next;
    }

    (void)heap;
    return head;
}

#endif /* CRL_STATIC_REVOKED_LIST */
/* returns a deep copy of ent on success and null on fail */
static CRL_Entry* DupCRL_Entry(const CRL_Entry* ent, void* heap)
{
    CRL_Entry *dupl;
    const size_t copyOffset = WC_OFFSETOF(CRL_Entry, verifyMutex) +
            sizeof(ent->verifyMutex);
#ifdef CRL_STATIC_REVOKED_LIST
    if (ent->totalCerts > CRL_MAX_REVOKED_CERTS) {
        return NULL;
    }
#endif
    dupl = CRL_Entry_new(heap);
    if (dupl == NULL) {
        WOLFSSL_MSG("alloc CRL Entry failed");
        return NULL;
    }

    XMEMCPY((byte*)dupl + copyOffset, (byte*)ent + copyOffset,
            sizeof(CRL_Entry) - copyOffset);

#ifndef CRL_STATIC_REVOKED_LIST
    dupl->certs = DupRevokedCertList(ent->certs, heap);
    if (ent->certs != NULL && dupl->certs == NULL) {
        CRL_Entry_free(dupl, heap);
        return NULL;
    }
#endif
#ifdef OPENSSL_EXTRA
    dupl->issuer = wolfSSL_X509_NAME_dup(ent->issuer);
    if (ent->issuer != NULL && dupl->issuer == NULL) {
        CRL_Entry_free(dupl, heap);
        return NULL;
    }
#endif

    if (!ent->verified) {
        dupl->toBeSigned = (byte*)XMALLOC(dupl->tbsSz, heap,
                                          DYNAMIC_TYPE_CRL_ENTRY);
        dupl->signature = (byte*)XMALLOC(dupl->signatureSz, heap,
                                         DYNAMIC_TYPE_CRL_ENTRY);
    #ifdef WC_RSA_PSS
        dupl->sigParams = (byte*)XMALLOC(dupl->sigParamsSz, heap,
                                         DYNAMIC_TYPE_CRL_ENTRY);
    #endif
        if (dupl->toBeSigned == NULL || dupl->signature == NULL
        #ifdef WC_RSA_PSS
            /* allow sigParamsSz is zero and XMALLOC(0) to return NULL */
            || (dupl->sigParams == NULL && dupl->sigParamsSz != 0)
        #endif
        ) {
            CRL_Entry_free(dupl, heap);
            return NULL;
        }
        XMEMCPY(dupl->toBeSigned, ent->toBeSigned, dupl->tbsSz);
        XMEMCPY(dupl->signature, ent->signature, dupl->signatureSz);
    #ifdef WC_RSA_PSS
        if (dupl->sigParamsSz > 0) {
            XMEMCPY(dupl->sigParams, ent->sigParams, dupl->sigParamsSz);
        }
    #endif
    }
    else {
        dupl->toBeSigned = NULL;
        dupl->tbsSz = 0;
        dupl->signature = NULL;
        dupl->signatureSz = 0;
#ifdef WC_RSA_PSS
        dupl->sigParams = NULL;
        dupl->sigParamsSz = 0;
#endif
#if !defined(NO_SKID) && !defined(NO_ASN)
        dupl->extAuthKeyIdSet = 0;
#endif
    }

    return dupl;
}


/* returns the head of a deep copy of the list on success and null on fail */
static CRL_Entry* DupCRL_list(CRL_Entry* crl, void* heap)
{
    CRL_Entry* current;
    CRL_Entry* head = NULL;
    CRL_Entry** prev = &head;

    for (current = crl; current != NULL; current = current->next) {
        CRL_Entry* tmp = DupCRL_Entry(current, heap);
        if (tmp != NULL) {
            *prev = tmp;
            prev = &tmp->next;
        }
        else {
            WOLFSSL_MSG("Failed to allocate new CRL_Entry structure");
            /* free up any existing list */
            while (head != NULL) {
                CRL_Entry* next = head->next;
                CRL_Entry_free(head, heap);
                head = next;
            }
            return NULL;
        }
    }

    return head;
}


/* Duplicates everything except the parent cm pointed to.
 * Expects that Init has already been done to 'dupl'
 * return 0 on success */
static int DupX509_CRL(WOLFSSL_X509_CRL *dupl, const WOLFSSL_X509_CRL* crl)
{
    if (dupl == NULL || crl == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef HAVE_CRL_MONITOR
    if (crl->monitors[0].path) {
        size_t pathSz = XSTRLEN(crl->monitors[0].path) + 1;
        dupl->monitors[0].path = (char*)XMALLOC(pathSz, dupl->heap,
                DYNAMIC_TYPE_CRL_MONITOR);
        if (dupl->monitors[0].path != NULL) {
            XSTRNCPY(dupl->monitors[0].path, crl->monitors[0].path, pathSz);
        }
        else {
            return MEMORY_E;
        }
    }

    if (crl->monitors[1].path) {
        size_t pathSz = XSTRLEN(crl->monitors[1].path) + 1;
        dupl->monitors[1].path = (char*)XMALLOC(pathSz, dupl->heap,
                DYNAMIC_TYPE_CRL_MONITOR);
        if (dupl->monitors[1].path != NULL) {
            XSTRNCPY(dupl->monitors[1].path, crl->monitors[1].path, pathSz);
        }
        else {
            if (dupl->monitors[0].path != NULL) {
                XFREE(dupl->monitors[0].path, dupl->heap,
                        DYNAMIC_TYPE_CRL_MONITOR);
                dupl->monitors[0].path = NULL;
            }
            return MEMORY_E;
        }
    }
#endif

    dupl->crlList = DupCRL_list(crl->crlList, dupl->heap);
    if (dupl->crlList == NULL)
        return MEMORY_E;
#ifdef HAVE_CRL_IO
    dupl->crlIOCb = crl->crlIOCb;
#endif

    return 0;
}

WOLFSSL_X509_CRL* wolfSSL_X509_CRL_dup(const WOLFSSL_X509_CRL* crl)
{
    WOLFSSL_X509_CRL* ret;

    WOLFSSL_ENTER("wolfSSL_X509_CRL_dup");

    ret = wolfSSL_X509_crl_new(crl->cm);
    if (ret != NULL && DupX509_CRL(ret, crl) != 0) {
        FreeCRL(ret, 1);
        ret = NULL;
    }
    return ret;
}

#ifdef OPENSSL_ALL
int wolfSSL_X509_CRL_up_ref(WOLFSSL_X509_CRL* crl)
{
    int ret;

    if (crl == NULL)
        return WOLFSSL_FAILURE;

    wolfSSL_RefInc(&crl->ref, &ret);
#ifdef WOLFSSL_REFCNT_ERROR_RETURN
    if (ret != 0) {
        WOLFSSL_MSG("Failed to lock x509 mutex");
        return WOLFSSL_FAILURE;
    }
#else
    (void)ret;
#endif

    return WOLFSSL_SUCCESS;
}
#endif

/* returns WOLFSSL_SUCCESS on success. Does not take ownership of newcrl */
int wolfSSL_X509_STORE_add_crl(WOLFSSL_X509_STORE *store, WOLFSSL_X509_CRL *newcrl)
{
    WOLFSSL_X509_CRL *crl;
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_X509_STORE_add_crl");
    if (store == NULL || newcrl == NULL || store->cm == NULL)
        return BAD_FUNC_ARG;

    if (store->cm->crl == NULL) {
        crl = wolfSSL_X509_crl_new(store->cm);
        if (crl == NULL) {
            WOLFSSL_MSG("wolfSSL_X509_crl_new failed");
            return WOLFSSL_FAILURE;
        }
        if (wc_LockRwLock_Rd(&newcrl->crlLock) != 0) {
            WOLFSSL_MSG("wc_LockRwLock_Rd failed");
            return BAD_MUTEX_E;
        }
        ret = DupX509_CRL(crl, newcrl);
        wc_UnLockRwLock(&newcrl->crlLock);
        if (ret != 0) {
            FreeCRL(crl, 1);
            return WOLFSSL_FAILURE;
        }
        store->crl = store->cm->crl = crl;
        if (wolfSSL_CertManagerEnableCRL(store->cm, WOLFSSL_CRL_CHECKALL)
                != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_CertManagerEnableCRL error");
            return WOLFSSL_FAILURE;
        }
        return WOLFSSL_SUCCESS;
    }

    /* find tail of current list and add new list */
    crl  = store->cm->crl;
    if (newcrl->crlList != NULL) {
        CRL_Entry **tail;
        CRL_Entry *toAdd;

        if (wc_LockRwLock_Wr(&crl->crlLock) != 0) {
            WOLFSSL_MSG("wc_LockRwLock_Wr failed");
            return BAD_MUTEX_E;
        }

        if (crl != newcrl && wc_LockRwLock_Rd(&newcrl->crlLock) != 0) {
            WOLFSSL_MSG("wc_LockRwLock_Rd failed");
            wc_UnLockRwLock(&crl->crlLock);
            return BAD_MUTEX_E;
        }
        toAdd = DupCRL_list(newcrl->crlList, crl->heap);
        if (crl != newcrl)
            wc_UnLockRwLock(&newcrl->crlLock);

        tail = &crl->crlList;
        while (*tail != NULL)
            tail = &(*tail)->next;
        *tail = toAdd;
        wc_UnLockRwLock(&crl->crlLock);
    }

    if (wolfSSL_CertManagerEnableCRL(store->cm, WOLFSSL_CRL_CHECKALL)
            != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("wolfSSL_CertManagerEnableCRL error");
        return WOLFSSL_FAILURE;
    }

    WOLFSSL_LEAVE("wolfSSL_X509_STORE_add_crl", WOLFSSL_SUCCESS);

    return WOLFSSL_SUCCESS;
}
#endif

#ifdef HAVE_CRL_MONITOR


/* Signal Monitor thread is setup, save status to setup flag, 0 on success */
static int SignalSetup(WOLFSSL_CRL* crl, int status)
{
    int ret, condRet;

    ret = wolfSSL_CondStart(&crl->cond);
    if (ret != 0)
        return ret;

    crl->setup = status;

    condRet = wolfSSL_CondSignal(&crl->cond);
    ret = wolfSSL_CondEnd(&crl->cond);
    if (ret != 0)
        return ret;

    return condRet;
}


/* read in new CRL entries and save new list */
static int SwapLists(WOLFSSL_CRL* crl)
{
    int        ret;
    CRL_Entry* newList;
    WC_DECLARE_VAR(tmp, WOLFSSL_CRL, 1, 0);

    WC_ALLOC_VAR_EX(tmp, WOLFSSL_CRL, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        return MEMORY_E);

    if (InitCRL(tmp, crl->cm) < 0) {
        WOLFSSL_MSG("Init tmp CRL failed");
        WC_FREE_VAR_EX(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FATAL_ERROR;
    }

    if (crl->monitors[0].path) {
        ret = LoadCRL(tmp, crl->monitors[0].path, WOLFSSL_FILETYPE_PEM, 0);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("PEM LoadCRL on dir change failed");
            FreeCRL(tmp, 0);
            WC_FREE_VAR_EX(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFSSL_FATAL_ERROR;
        }
    }

    if (crl->monitors[1].path) {
        ret = LoadCRL(tmp, crl->monitors[1].path, WOLFSSL_FILETYPE_ASN1, 0);
        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("DER LoadCRL on dir change failed");
            FreeCRL(tmp, 0);
            WC_FREE_VAR_EX(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFSSL_FATAL_ERROR;
        }
    }

    if (wc_LockRwLock_Wr(&crl->crlLock) != 0) {
        WOLFSSL_MSG("wc_LockRwLock_Wr failed");
        FreeCRL(tmp, 0);
        WC_FREE_VAR_EX(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFSSL_FATAL_ERROR;
    }

    newList = tmp->crlList;

    /* swap lists */
    tmp->crlList  = crl->crlList;
    crl->crlList = newList;

    wc_UnLockRwLock(&crl->crlLock);

    FreeCRL(tmp, 0);

    WC_FREE_VAR_EX(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return 0;
}


#if (defined(__MACH__) || defined(__FreeBSD__))

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef __MACH__
    #define XEVENT_MODE O_EVTONLY
#elif defined(__FreeBSD__)
    #define XEVENT_MODE O_RDONLY
#endif


/* we need a unique kqueue user filter fd for crl in case user is doing custom
 * events too */
#ifndef CRL_CUSTOM_FD
    #define CRL_CUSTOM_FD 123456
#endif


/* shutdown monitor thread, 0 on success */
static int StopMonitor(wolfSSL_CRL_mfd_t mfd)
{
    struct kevent change;

    /* trigger custom shutdown */
#if defined(NOTE_TRIGGER)
    EV_SET(&change, CRL_CUSTOM_FD, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
#elif defined(EV_TRIGGER)
    EV_SET(&change, CRL_CUSTOM_FD, EVFILT_USER, EV_TRIGGER, 0, 0, NULL);
#endif
    if (kevent(mfd, &change, 1, NULL, 0, NULL) < 0) {
        WOLFSSL_MSG("kevent trigger customer event failed");
        return WOLFSSL_FATAL_ERROR;
    }

    return 0;
}


/* OS X  monitoring */
static THREAD_RETURN WOLFSSL_THREAD DoMonitor(void* arg)
{
    int fPEM, fDER;
    struct kevent change;

    WOLFSSL_CRL* crl = (WOLFSSL_CRL*)arg;

    WOLFSSL_ENTER("DoMonitor");

    crl->mfd = kqueue();
    if (crl->mfd == -1) {
        WOLFSSL_MSG("kqueue failed");
        SignalSetup(crl, MONITOR_SETUP_E);
        return NULL;
    }

    /* listen for custom shutdown event */
    EV_SET(&change, CRL_CUSTOM_FD, EVFILT_USER, EV_ADD, 0, 0, NULL);
    if (kevent(crl->mfd, &change, 1, NULL, 0, NULL) < 0) {
        WOLFSSL_MSG("kevent monitor customer event failed");
        SignalSetup(crl, MONITOR_SETUP_E);
        (void)close(crl->mfd);
        return NULL;
    }

    fPEM = -1;
    fDER = -1;

    if (crl->monitors[0].path) {
        fPEM = open(crl->monitors[0].path, XEVENT_MODE);
        if (fPEM == -1) {
            WOLFSSL_MSG("PEM event dir open failed");
            SignalSetup(crl, MONITOR_SETUP_E);
            (void)close(crl->mfd);
            return NULL;
        }
    }

    if (crl->monitors[1].path) {
        fDER = open(crl->monitors[1].path, XEVENT_MODE);
        if (fDER == -1) {
            WOLFSSL_MSG("DER event dir open failed");
            if (fPEM != -1)
                (void)close(fPEM);
            (void)close(crl->mfd);
            SignalSetup(crl, MONITOR_SETUP_E);
            return NULL;
        }
    }

    if (fPEM != -1)
        EV_SET(&change, fPEM, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
                NOTE_DELETE | NOTE_EXTEND | NOTE_WRITE | NOTE_ATTRIB, 0, 0);

    if (fDER != -1)
        EV_SET(&change, fDER, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
                NOTE_DELETE | NOTE_EXTEND | NOTE_WRITE | NOTE_ATTRIB, 0, 0);

    /* signal to calling thread we're setup */
    if (SignalSetup(crl, 1) != 0) {
        if (fPEM != -1)
            (void)close(fPEM);
        if (fDER != -1)
            (void)close(fDER);
        (void)close(crl->mfd);
        return NULL;
    }

    for (;;) {
        struct kevent event;
        int           numEvents = kevent(crl->mfd, &change, 1, &event, 1, NULL);

        WOLFSSL_MSG("Got kevent");

        if (numEvents == -1) {
            WOLFSSL_MSG("kevent problem, continue");
            continue;
        }

        if (event.filter == EVFILT_USER) {
            WOLFSSL_MSG("Got user shutdown event, breaking out");
            break;
        }

        if (SwapLists(crl) < 0) {
            WOLFSSL_MSG("SwapLists problem, continue");
        }
    }

    if (fPEM != -1)
        (void)close(fPEM);
    if (fDER != -1)
        (void)close(fDER);

    (void)close(crl->mfd);

    return NULL;
}


#elif defined(__linux__)

#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/eventfd.h>
#include <unistd.h>


#ifndef max
    static WC_INLINE int max(int a, int b)
    {
        return a > b ? a : b;
    }
#endif /* max */


/* shutdown monitor thread, 0 on success */
static int StopMonitor(wolfSSL_CRL_mfd_t mfd)
{
    word64 w64 = 1;

    /* write to our custom event */
    if (write(mfd, &w64, sizeof(w64)) < 0) {
        WOLFSSL_MSG("StopMonitor write failed");
        return WOLFSSL_FATAL_ERROR;
    }

    return 0;
}


/* linux monitoring */
static THREAD_RETURN WOLFSSL_THREAD DoMonitor(void* arg)
{
    int         notifyFd;
    int         wd  = -1;
    WOLFSSL_CRL* crl = (WOLFSSL_CRL*)arg;
    WC_DECLARE_VAR(buff, char, 8192, 0);

    WOLFSSL_ENTER("DoMonitor");

    crl->mfd = eventfd(0, 0);  /* our custom shutdown event */
    if (crl->mfd < 0) {
        WOLFSSL_MSG("eventfd failed");
        SignalSetup(crl, MONITOR_SETUP_E);
        return NULL;
    }

    notifyFd = inotify_init();
    if (notifyFd < 0) {
        WOLFSSL_MSG("inotify failed");
        (void)close(crl->mfd);
        SignalSetup(crl, MONITOR_SETUP_E);
        return NULL;
    }

    if (crl->monitors[0].path) {
        wd = inotify_add_watch(notifyFd, crl->monitors[0].path, IN_CLOSE_WRITE |
                                                                IN_DELETE);
        if (wd < 0) {
            WOLFSSL_MSG("PEM notify add watch failed");
            (void)close(crl->mfd);
            (void)close(notifyFd);
            SignalSetup(crl, MONITOR_SETUP_E);
            return NULL;
        }
    }

    if (crl->monitors[1].path) {
        wd = inotify_add_watch(notifyFd, crl->monitors[1].path, IN_CLOSE_WRITE |
                                                                IN_DELETE);
        if (wd < 0) {
            WOLFSSL_MSG("DER notify add watch failed");
            (void)close(crl->mfd);
            (void)close(notifyFd);
            SignalSetup(crl, MONITOR_SETUP_E);
            return NULL;
        }
    }


    /* signal to calling thread we're setup */
    if (SignalSetup(crl, 1) != 0) {
        if (wd > 0) {
            if (inotify_rm_watch(notifyFd, wd) < 0)
                WOLFSSL_MSG("inotify_rm_watch #1 failed in DoMonitor");
        }
        (void)close(crl->mfd);
        (void)close(notifyFd);
        return NULL;
    }

#ifdef WOLFSSL_SMALL_STACK
    buff = (char*)XMALLOC(8192, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buff == NULL)
        return NULL;
#endif

    for (;;) {
        fd_set readfds;
        int    result;
        int    length;

        FD_ZERO(&readfds);
        FD_SET(notifyFd, &readfds);
        FD_SET(crl->mfd, &readfds);

        result = select(max(notifyFd, crl->mfd) + 1, &readfds, NULL, NULL,NULL);

        WOLFSSL_MSG("Got notify event");

        if (result < 0) {
            WOLFSSL_MSG("select problem, continue");
            continue;
        }

        if (FD_ISSET(crl->mfd, &readfds)) {
            word64 r64;
            int    rlen;

            WOLFSSL_MSG("got custom shutdown event, breaking out");

            /* read out the bytes written to the event to clean up */
            rlen = (int) read(crl->mfd, &r64, sizeof(r64));
            if (rlen < 0) {
                WOLFSSL_MSG("read custom event failure");
            }

            break;
        }

        length = (int) read(notifyFd, buff, 8192);
        if (length < 0) {
            WOLFSSL_MSG("notify read problem, continue");
            continue;
        }

        if (SwapLists(crl) < 0) {
            WOLFSSL_MSG("SwapLists problem, continue");
        }
    }

    WC_FREE_VAR_EX(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (wd > 0) {
        if (inotify_rm_watch(notifyFd, wd) < 0)
            WOLFSSL_MSG("inotify_rm_watch #2 failed in DoMonitor");
    }
    (void)close(crl->mfd);
    (void)close(notifyFd);

    return NULL;
}

#elif defined(_MSC_VER)

/* shutdown monitor thread, 0 on success */
static int StopMonitor(wolfSSL_CRL_mfd_t mfd)
{
    if (SetEvent(mfd) == 0) {
        WOLFSSL_MSG("SetEvent custom event trigger failed");
        return WOLFSSL_FATAL_ERROR;
    }
    return 0;
}

#ifdef DEBUG_WOLFSSL
#define SHOW_WINDOWS_ERROR() do {                               \
    LPVOID lpMsgBuf = NULL;                                     \
    DWORD dw = GetLastError();                                  \
    FormatMessageA(                                             \
        FORMAT_MESSAGE_ALLOCATE_BUFFER |                        \
        FORMAT_MESSAGE_FROM_SYSTEM |                            \
        FORMAT_MESSAGE_IGNORE_INSERTS,                          \
        NULL,                                                   \
        dw,                                                     \
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),              \
        (LPSTR) &lpMsgBuf,                                      \
        0, NULL );                                              \
    WOLFSSL_MSG_EX("DoMonitor failed with error %d: %s\n",      \
        dw, lpMsgBuf);                                          \
    LocalFree(lpMsgBuf);                                        \
} while(0)
#else
#define SHOW_WINDOWS_ERROR() WC_DO_NOTHING
#endif

#define DM_ERROR() do {                                         \
    SHOW_WINDOWS_ERROR();                                       \
    status = MONITOR_SETUP_E;                                   \
    goto cleanup;                                               \
} while(0)

/* windows monitoring
 * Tested initially by hand by running
 * .\server.exe -A certs/ca-cert.pem -i -x
 * and connecting to with
 * .\client.exe -C -c certs/server-cert.pem -k certs/server-key.pem
 * This connection succeeds by default. By deleting all files from certs/crl
 * except for crl.revoked we disallow the client to connect. Deleting files
 * is done while the server is running to show that the monitor reacts to
 * changes in the crl directory. */
static THREAD_RETURN WOLFSSL_THREAD DoMonitor(void* arg)
{
    WOLFSSL_CRL* crl = (WOLFSSL_CRL*)arg;
    int status = 0;
    HANDLE handles[WOLFSSL_CRL_MONITORS_LEN + 1];
    DWORD handlesLen = 0;
    int i;

    WOLFSSL_ENTER("DoMonitor");

    handles[0] = crl->mfd = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (crl->mfd == NULL) {
        WOLFSSL_MSG("CreateEventA failed");
        DM_ERROR();
    }
    handlesLen++;

    for (i = 0; i < WOLFSSL_CRL_MONITORS_LEN; i++) {
        if (crl->monitors[i].path) {
            handles[handlesLen] = FindFirstChangeNotificationA(
                crl->monitors[i].path, TRUE,
                /* Watch for any changes that may affect what CRL's we load.
                 * This may trigger on the same file multiple times but this
                 * way we are certain that we have the most up to date and
                 * accurate set of CRL's. We don't expect this to trigger
                 * often enough for it to be a bottleneck. */
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES |
                FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_SECURITY);
            if (handles[handlesLen] == INVALID_HANDLE_VALUE) {
                WOLFSSL_MSG("FindFirstChangeNotificationA failed");
                DM_ERROR();
            }
            handlesLen++;
        }
    }

    if (handlesLen == 1) {
        WOLFSSL_MSG("Nothing to watch. Only custom event handle set.");
        DM_ERROR();
    }

    if (SignalSetup(crl, 1) != 0) {
        WOLFSSL_MSG("Call to SignalSetup failed");
        DM_ERROR();
    }

    for (;;) {
        DWORD waitRet = WaitForMultipleObjects(handlesLen, handles, FALSE,
                                               INFINITE);
        WOLFSSL_MSG("Got notify event");

        if (waitRet >= WAIT_OBJECT_0 && waitRet < WAIT_OBJECT_0 + handlesLen) {
            if (waitRet == WAIT_OBJECT_0) {
                WOLFSSL_MSG("got custom shutdown event, breaking out");
                break;
            }
            else if (SwapLists(crl) < 0) {
                WOLFSSL_MSG("SwapLists problem, continue");
            }
        }
        else {
            WOLFSSL_MSG("Unexpected WaitForMultipleObjects return. Continue.");
        }

        for (i = 1; i < (int)handlesLen; i++) {
            if (FindNextChangeNotification(handles[i]) == 0) {
                WOLFSSL_MSG("FindNextChangeNotification failed");
                DM_ERROR();
            }
        }
    }

cleanup:
    if (status != 0)
        SignalSetup(crl, status);
    for (i = 0; i < (int)handlesLen; i++) {
        BOOL closeRet;
        if (i == 0) /* First handle is our custom event */
            closeRet = CloseHandle(handles[i]);
        else
            closeRet = FindCloseChangeNotification(handles[i]);
        if (closeRet == 0) {
            WOLFSSL_MSG("Failed to close handle");
        }
    }
    crl->mfd = INVALID_HANDLE_VALUE;
    return 0;
}

#endif /* MACH or linux or windows */


/* Start Monitoring the CRL path(s) in a thread */
static int StartMonitorCRL(WOLFSSL_CRL* crl)
{
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("StartMonitorCRL");

    if (crl == NULL)
        return BAD_FUNC_ARG;

    if (crl->tid != INVALID_THREAD_VAL) {
        WOLFSSL_MSG("Monitor thread already running");
        return ret;  /* that's ok, someone already started */
    }

    if (wolfSSL_NewThread(&crl->tid, DoMonitor, crl) != 0) {
        WOLFSSL_MSG("Thread creation error");
        return THREAD_CREATE_E;
    }

    /* wait for setup to complete */
    if (wolfSSL_CondStart(&crl->cond) != 0) {
        WOLFSSL_MSG("wolfSSL_CondStart failed");
        return BAD_MUTEX_E;
    }
    while (crl->setup == 0) {
        int condRet;
        condRet = wolfSSL_CondWait(&crl->cond);
        if (condRet != 0) {
            ret = BAD_COND_E;
            break;
        }
    }
    if (ret >= 0 && crl->setup < 0)
        ret = crl->setup;  /* store setup error */

    if (ret < 0) {
        WOLFSSL_MSG("DoMonitor setup failure");
        crl->tid = INVALID_THREAD_VAL;  /* thread already done */
    }
    if (wolfSSL_CondEnd(&crl->cond) != 0) {
        WOLFSSL_MSG("wolfSSL_CondEnd failed");
        return BAD_MUTEX_E;
    }

    return ret;
}

#endif  /* HAVE_CRL_MONITOR */

#if !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)

/* Load CRL path files of type, WOLFSSL_SUCCESS on ok */
int LoadCRL(WOLFSSL_CRL* crl, const char* path, int type, int monitor)
{
    int         ret = WOLFSSL_SUCCESS;
    char*       name = NULL;
    WC_DECLARE_VAR(readCtx, ReadDirCtx, 1, 0);

    WOLFSSL_ENTER("LoadCRL");
    if (crl == NULL)
        return BAD_FUNC_ARG;

    WC_ALLOC_VAR_EX(readCtx, ReadDirCtx, 1, crl->heap,
        DYNAMIC_TYPE_TMP_BUFFER, return MEMORY_E);

    /* try to load each regular file in path */
    ret = wc_ReadDirFirst(readCtx, path, &name);
    while (ret == 0 && name) {
        int skip = 0;
        if (type == WOLFSSL_FILETYPE_PEM) {
            if (XSTRSTR(name, ".pem") == NULL) {
                WOLFSSL_MSG("not .pem file, skipping");
                skip = 1;
            }
        }
        else {
            if (XSTRSTR(name, ".der") == NULL &&
                XSTRSTR(name, ".crl") == NULL)
            {
                WOLFSSL_MSG("not .der or .crl file, skipping");
                skip = 1;
            }
        }

#ifndef CRL_REPORT_LOAD_ERRORS
        if (!skip && ProcessFile(NULL, name, type, CRL_TYPE, NULL, 0, crl,
                                 VERIFY) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("CRL file load failed, continuing");
        }
#else
        if (!skip) {
            ret = ProcessFile(NULL, name, type, CRL_TYPE, NULL, 0, crl, VERIFY);
            if (ret != WOLFSSL_SUCCESS) {
                WOLFSSL_MSG("CRL file load failed");
                wc_ReadDirClose(readCtx);
                WC_FREE_VAR_EX(readCtx, crl->heap, DYNAMIC_TYPE_TMP_BUFFER);
                return ret;
            }
        }
#endif

        ret = wc_ReadDirNext(readCtx, path, &name);
    }
    wc_ReadDirClose(readCtx);

    /* load failures not reported, for backwards compat */
    ret = WOLFSSL_SUCCESS;

    WC_FREE_VAR_EX(readCtx, crl->heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (monitor & WOLFSSL_CRL_MONITOR) {
#ifdef HAVE_CRL_MONITOR
        word32 pathLen;
        char* pathBuf;

        WOLFSSL_MSG("monitor path requested");

        pathLen = (word32)XSTRLEN(path);
        pathBuf = (char*)XMALLOC(pathLen+1, crl->heap, DYNAMIC_TYPE_CRL_MONITOR);
        if (pathBuf) {
            XMEMCPY(pathBuf, path, pathLen+1);

            if (type == WOLFSSL_FILETYPE_PEM) {
                /* free old path before setting a new one */
                if (crl->monitors[0].path) {
                    XFREE(crl->monitors[0].path, crl->heap,
                            DYNAMIC_TYPE_CRL_MONITOR);
                }
                crl->monitors[0].path = pathBuf;
                crl->monitors[0].type = WOLFSSL_FILETYPE_PEM;
            } else {
                /* free old path before setting a new one */
                if (crl->monitors[1].path) {
                    XFREE(crl->monitors[1].path, crl->heap,
                            DYNAMIC_TYPE_CRL_MONITOR);
                }
                crl->monitors[1].path = pathBuf;
                crl->monitors[1].type = WOLFSSL_FILETYPE_ASN1;
            }

            if (monitor & WOLFSSL_CRL_START_MON) {
                WOLFSSL_MSG("start monitoring requested");

                ret = StartMonitorCRL(crl);
            }
        }
        else {
            ret = MEMORY_E;
        }
#else
        WOLFSSL_MSG("CRL monitoring requested but not compiled in");
        ret = NOT_COMPILED_IN;
#endif
    }

    return ret;
}

#else
int LoadCRL(WOLFSSL_CRL* crl, const char* path, int type, int monitor)
{
    (void)crl;
    (void)path;
    (void)type;
    (void)monitor;

    /* stub for scenario where file system is not supported */
    return NOT_COMPILED_IN;
}
#endif /* !NO_FILESYSTEM && !NO_WOLFSSL_DIR */

#ifndef NO_FILESYSTEM
/* Store CRL to a file in DER or PEM format.
 * Returns WOLFSSL_SUCCESS on success, negative on failure.
 * @param [in] crl    CRL object.
 * @param [in] path   Path to the file to store the CRL.
 * @param [in] type   Format of encoding. Valid values:
 *                      WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM.
 * @return  WOLFSSL_SUCCESS on success, or negative on failure.
 */
int StoreCRL(WOLFSSL_CRL* crl, const char* path, int type)
{
    XFILE fp = XBADFILE;
    int ret = WOLFSSL_SUCCESS;
    long sz = 0;
    byte* mem = NULL;

    WOLFSSL_ENTER("StoreCRL");

    if (crl == NULL || path == NULL)
        return BAD_FUNC_ARG;

    /* Determine required size. */
    ret = BufferStoreCRL(crl, NULL, &sz, type);
    if (ret != WOLFSSL_SUCCESS) {
        return ret;
    }

    /* Allocate temporary buffer. */
    mem = (byte*)XMALLOC((size_t)sz, crl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (mem == NULL) {
        return MEMORY_E;
    }

    /* Encode CRL into buffer. */
    ret = BufferStoreCRL(crl, mem, &sz, type);
    if (ret == WOLFSSL_SUCCESS) {
        /* Open destination file for writing. */
        fp = XFOPEN(path, "wb");
        if (fp == XBADFILE) {
            ret = WOLFSSL_BAD_FILE;
        }
        else {
            size_t wrote = XFWRITE(mem, 1, (size_t)sz, fp);
            if (wrote != (size_t)sz) {
                WOLFSSL_MSG("CRL file write failed");
                ret = FWRITE_ERROR;
            }
            XFCLOSE(fp);
        }
    }

    XFREE(mem, crl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#else
int StoreCRL(WOLFSSL_CRL* crl, const char* file, int type)
{
    (void)crl;
    (void)file;
    (void)type;
    return NOT_COMPILED_IN;
}
#endif /* NO_FILESYSTEM */

#if defined(OPENSSL_EXTRA)
/* Create a new empty CRL object for generation.
 * Version is set to 2 by default. Use wolfSSL_X509_CRL_set_version() to
 * change it.
 * lastUpdate set to current time, nextUpdate set to 500 days from now.
 * Returns a new CRL or NULL on failure.
 */
WOLFSSL_X509_CRL* wolfSSL_X509_CRL_new(void)
{
    WOLFSSL_X509_CRL* crl;
    CRL_Entry* entry;
    WOLFSSL_ASN1_TIME asnTime;

    WOLFSSL_ENTER("wolfSSL_X509_CRL_new");

    crl = (WOLFSSL_X509_CRL*)XMALLOC(sizeof(WOLFSSL_X509_CRL), NULL,
                                      DYNAMIC_TYPE_CRL);
    if (crl == NULL) {
        WOLFSSL_MSG("Memory allocation failed for CRL");
        return NULL;
    }

    if (InitCRL(crl, NULL) < 0) {
        WOLFSSL_MSG("Init CRL failed");
        XFREE(crl, NULL, DYNAMIC_TYPE_CRL);
        return NULL;
    }

    /* Allocate empty CRL entry for setting fields */
    entry = (CRL_Entry*)XMALLOC(sizeof(CRL_Entry), NULL,
                                DYNAMIC_TYPE_CRL_ENTRY);
    if (entry == NULL) {
        WOLFSSL_MSG("Memory allocation failed for CRL entry");
        FreeCRL(crl, 1);
        return NULL;
    }
    XMEMSET(entry, 0, sizeof(CRL_Entry));

    if (wc_InitMutex(&entry->verifyMutex) != 0) {
        XFREE(entry, NULL, DYNAMIC_TYPE_CRL_ENTRY);
        FreeCRL(crl, 1);
        return NULL;
    }

    crl->crlList = entry;

    /* Set thisUpdate to current time */
    if (wolfSSL_ASN1_TIME_adj(&asnTime, XTIME(NULL), 0, 0) == NULL) {
        WOLFSSL_MSG("Failed to get current time");
        FreeCRL(crl, 1);
        return NULL;
    }
    if (wolfSSL_X509_CRL_set_lastUpdate(crl, &asnTime) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Failed to set last update");
        FreeCRL(crl, 1);
        return NULL;
    }

    /* Set next update date to 500 days from now,
     * following convention from wc_InitCert() */
    if (wolfSSL_ASN1_TIME_adj(&asnTime, XTIME(NULL), 500, 0) == NULL) {
        WOLFSSL_MSG("Failed to get next update time");
        FreeCRL(crl, 1);
        return NULL;
    }
    if (wolfSSL_X509_CRL_set_nextUpdate(crl, &asnTime) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Failed to set next update");
        FreeCRL(crl, 1);
        return NULL;
    }

    /* Set default version to v2 (required for extensions) */
    entry->version = 2;

    return crl;
}

#ifdef WOLFSSL_CERT_GEN
/* Add a revoked certificate entry to CRL.
 * crl: target CRL
 * rev: revoked certificate entry (serial, date, reason, etc.)
 * Returns WOLFSSL_SUCCESS on success.
 */
int wolfSSL_X509_CRL_add_revoked(WOLFSSL_X509_CRL* crl,
                                 WOLFSSL_X509_REVOKED* rev)
{
    CRL_Entry* entry;
    RevokedCert* rc;
    RevokedCert* curr;

    WOLFSSL_ENTER("wolfSSL_X509_CRL_add_revoked");

    if (crl == NULL || rev == NULL || rev->serialNumber == NULL) {
        return BAD_FUNC_ARG;
    }

    if (rev->revocationDate != NULL && (rev->revocationDate->length <= 0 ||
        (unsigned)rev->revocationDate->length > sizeof(rc->revDate))) {
        return BAD_FUNC_ARG;
    }

    entry = crl->crlList;
    if (entry == NULL) {
        return BAD_FUNC_ARG;
    }

    {
        const byte* serial = rev->serialNumber->data;
        int serialSz = rev->serialNumber->length;
        int i;
        int allZero = 1;

        if (serial == NULL || serialSz <= 0) {
            return BAD_FUNC_ARG;
        }

        if (serialSz > EXTERNAL_SERIAL_SIZE) {
            return BAD_FUNC_ARG;
        }

        /* All zero serial numbers are invalid per rfc5280 and not supported */
        for (i = 0; i < serialSz; i++) {
            if (serial[i] != 0) {
                allZero = 0;
                break;
            }
        }
        if (allZero) {
            return BAD_FUNC_ARG;
        }

        rc = (RevokedCert*)XMALLOC(sizeof(RevokedCert), crl->heap,
                                   DYNAMIC_TYPE_REVOKED);
        if (rc == NULL) {
            return MEMORY_E;
        }
        XMEMSET(rc, 0, sizeof(RevokedCert));

        XMEMCPY(rc->serialNumber, serial, (size_t)serialSz);
        rc->serialSz = serialSz;
    }

    /* Use caller-provided revocation date, or fall back to current time */
    if (rev->revocationDate != NULL && rev->revocationDate->length > 0) {
        XMEMCPY(rc->revDate, rev->revocationDate->data,
                 (size_t)rev->revocationDate->length);
        rc->revDateFormat = (byte)rev->revocationDate->type;
    }
    else {
        WOLFSSL_ASN1_TIME revDate;
        XMEMSET(&revDate, 0, sizeof(revDate));
        if (wolfSSL_ASN1_TIME_adj(&revDate, XTIME(NULL), 0, 0) == NULL) {
            WOLFSSL_MSG("Failed to get current time");
            XFREE(rc, crl->heap, DYNAMIC_TYPE_REVOKED);
            return BAD_STATE_E;
        }
        XMEMCPY(rc->revDate, revDate.data, revDate.length);
        rc->revDateFormat = (byte)revDate.type;
    }

    rc->reasonCode = rev->reason;
    rc->next = NULL;

    /* Add to end of list */
    if (entry->certs == NULL) {
        entry->certs = rc;
    }
    else {
        for (curr = entry->certs; curr->next != NULL; curr = curr->next)
            ;
        curr->next = rc;
    }
    entry->totalCerts++;

    /* Invalidate cached STACK_OF(X509_REVOKED) since list changed */
    if (crl->revokedStack != NULL) {
        wolfSSL_sk_pop_free(crl->revokedStack, NULL);
        crl->revokedStack = NULL;
    }

    WOLFSSL_LEAVE("wolfSSL_X509_CRL_add_revoked", WOLFSSL_SUCCESS);
    return WOLFSSL_SUCCESS;
}

/* Add a revoked certificate entry to CRL by parsing a certificate buffer.
 * crl: target CRL
 * certBuf: DER-encoded certificate buffer
 * certSz: size of certificate buffer
 * revDate: revocation date (ASN.1 format), or NULL for
 *          current time
 * revDateFmt: date format (ASN_UTC_TIME or ASN_GENERALIZED_TIME), ignored if
 *             revDate is NULL
 * Returns WOLFSSL_SUCCESS on success.
 * Note: this function is only available when WOLFSSL_CERT_GEN is defined.
 */
int wolfSSL_X509_CRL_add_revoked_cert(WOLFSSL_X509_CRL* crl,
                                      const unsigned char* certBuf, int certSz)
{
    int ret;
    DecodedCert* cert = NULL;
    WOLFSSL_X509_REVOKED revoked;
    WOLFSSL_ASN1_INTEGER* serialInt = NULL;

    WOLFSSL_ENTER("wolfSSL_X509_CRL_add_revoked_cert");

    if (crl == NULL || certBuf == NULL || certSz <= 0) {
        return BAD_FUNC_ARG;
    }

    cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_DCERT);
    if (cert == NULL) {
        return MEMORY_E;
    }

    /* Initialize and parse the certificate */
    InitDecodedCert(cert, certBuf, (word32)certSz, NULL);
    ret = ParseCertRelative(cert, CERT_TYPE, NO_VERIFY, NULL, NULL);
    if (ret != 0) {
        WOLFSSL_MSG("Failed to parse certificate");
        FreeDecodedCert(cert);
        XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
        return ret;
    }

    serialInt = wolfSSL_ASN1_INTEGER_new();
    if (serialInt == NULL) {
        FreeDecodedCert(cert);
        XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
        return MEMORY_E;
    }

    if (cert->serialSz > WOLFSSL_ASN1_INTEGER_MAX) {
        serialInt->data = (unsigned char*)XMALLOC(cert->serialSz, NULL,
            DYNAMIC_TYPE_OPENSSL);
        if (serialInt->data == NULL) {
            wolfSSL_ASN1_INTEGER_free(serialInt);
            FreeDecodedCert(cert);
            XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
            return MEMORY_E;
        }
        serialInt->dataMax = (unsigned int)cert->serialSz;
        serialInt->isDynamic = 1;
    }
    else {
        serialInt->data = serialInt->intData;
        serialInt->dataMax = WOLFSSL_ASN1_INTEGER_MAX;
    }

    XMEMCPY(serialInt->data, cert->serial, cert->serialSz);
    serialInt->length = cert->serialSz;

    XMEMSET(&revoked, 0, sizeof(revoked));
    revoked.serialNumber = serialInt;
    revoked.reason = CRL_REASON_NONE;

    /* Add the revoked certificate entry */
    ret = wolfSSL_X509_CRL_add_revoked(crl, &revoked);

    FreeDecodedCert(cert);
    XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
    wolfSSL_ASN1_INTEGER_free(serialInt);

    return ret;
}

static int GetCrlSignBufSz(int tbsSz, int sigType, RsaKey* rsaKey,
    ecc_key* eccKey)
{
    int sigSz = 0;
    int ret;
    byte sigDummy = 0;

    if (tbsSz <= 0)
        return BAD_FUNC_ARG;

#ifndef NO_RSA
    if (rsaKey != NULL) {
        sigSz = wc_RsaEncryptSize(rsaKey);
    }
#endif
#ifdef HAVE_ECC
    if (sigSz <= 0 && eccKey != NULL) {
        sigSz = wc_ecc_sig_size(eccKey);
    }
#endif
    if (sigSz <= 0) {
        /* Fallback for unexpected key sizes */
        sigSz = 1024;
    }

    /* Estimate total CRL size by asking AddSignature for the DER wrapper
     * size (sequence + algo OID + BIT STRING headers). If it fails (e.g.,
     * unknown sigType), fall back to a conservative headroom of 64 bytes for
     * those headers. This is defensive (size-estimate only); the real sign
     * path will still report any unsupported sigType. */
    ret = AddSignature(NULL, tbsSz, &sigDummy, sigSz, sigType);
    if (ret < 0) {
        ret = tbsSz + sigSz + 64;
    }
    return ret;
}

/* Sign a CRL with a private key, rebuilding TBS from fields.
 * crl: CRL with fields set via setter functions
 * pkey: private key for signing
 * md: digest algorithm (e.g., EVP_sha256())
 * Note: only one entry is supported in the CRL list.
 * Returns WOLFSSL_SUCCESS on success.
 */
int wolfSSL_X509_CRL_sign(WOLFSSL_X509_CRL* crl, WOLFSSL_EVP_PKEY* pkey,
                          const WOLFSSL_EVP_MD* md)
{
    int ret = WOLFSSL_SUCCESS;
    CRL_Entry* entry;
    byte* issuerDer = NULL;
    int issuerSz = 0;
    int sigType;
    int tbsSz = 0;
    int totalSz = 0;
    byte* buf = NULL;
    int bufSz = 0;
    RsaKey* rsaKey = NULL;
    ecc_key* eccKey = NULL;
    WC_RNG rng;
    int rngInit = 0;

    WOLFSSL_ENTER("wolfSSL_X509_CRL_sign");

    if (crl == NULL || pkey == NULL || md == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Fetch only the first entry in the CRL list */
    entry = crl->crlList;
    if (entry == NULL) {
        WOLFSSL_MSG("CRL has no entry");
        return BAD_FUNC_ARG;
    }

    /* Determine signature type from digest and key type */
#ifndef NO_RSA
    if (ret == WOLFSSL_SUCCESS) {
        if (pkey->type == WC_EVP_PKEY_RSA) {
            if (md == wolfSSL_EVP_sha256()) {
                sigType = CTC_SHA256wRSA;
            }
            #ifdef WOLFSSL_SHA384
            else if (md == wolfSSL_EVP_sha384()) {
                sigType = CTC_SHA384wRSA;
            }
            #endif
            #ifdef WOLFSSL_SHA512
            else if (md == wolfSSL_EVP_sha512()) {
                sigType = CTC_SHA512wRSA;
            }
            #endif
            else if (md == wolfSSL_EVP_sha1()) {
                sigType = CTC_SHAwRSA;
            }
            else {
                WOLFSSL_MSG("Unsupported digest for RSA");
                return BAD_FUNC_ARG;
            }
            rsaKey = (RsaKey*)pkey->rsa->internal;
        }
        else
#endif
#ifdef HAVE_ECC
        if (pkey->type == WC_EVP_PKEY_EC) {
            if (md == wolfSSL_EVP_sha256()) {
                sigType = CTC_SHA256wECDSA;
            }
            #ifdef WOLFSSL_SHA384
            else if (md == wolfSSL_EVP_sha384()) {
                sigType = CTC_SHA384wECDSA;
            }
            #endif
            #ifdef WOLFSSL_SHA512
            else if (md == wolfSSL_EVP_sha512()) {
                sigType = CTC_SHA512wECDSA;
            }
            #endif
            else if (md == wolfSSL_EVP_sha1()) {
                sigType = CTC_SHAwECDSA;
            }
            else {
                WOLFSSL_MSG("Unsupported digest for ECDSA");
                return BAD_FUNC_ARG;
            }
            eccKey = (ecc_key*)pkey->ecc->internal;
        }
        else
#endif
        {
            WOLFSSL_MSG("Unsupported key type");
            return BAD_FUNC_ARG;
        }
    }

    /* Get issuer name DER */
    if (ret == WOLFSSL_SUCCESS) {
        if (entry->issuer != NULL) {
            /* Retrieve the issuer in two passes so we can avoid making
             * assumptions about the heap that is used, as we must free
             * this buffer later. */
            issuerSz = wolfSSL_i2d_X509_NAME(entry->issuer, NULL);
            if (issuerSz <= 0) {
                WOLFSSL_MSG("Failed to encode issuer name");
                ret = WOLFSSL_FAILURE;
            }
            else {
                issuerDer = (byte*)XMALLOC((size_t)issuerSz, crl->heap,
                                           DYNAMIC_TYPE_TMP_BUFFER);
                if (issuerDer == NULL) {
                    WOLFSSL_MSG("Memory allocation failed for issuer DER");
                    ret = MEMORY_E;
                }
                else {
                    /* i2d moves the pointer, so use a temp */
                    byte* tempPtr = issuerDer;
                    if (wolfSSL_i2d_X509_NAME(entry->issuer, &tempPtr) <= 0) {
                        WOLFSSL_MSG("Failed to encode issuer name");
                        ret = WOLFSSL_FAILURE;
                    }
                }
            }
        }
        else {
            WOLFSSL_MSG("CRL has no issuer set");
            ret = BAD_FUNC_ARG;
        }
    }

    /* Copy dates from ASN1 time structures to raw fields if needed */
    if (ret == WOLFSSL_SUCCESS) {
        if (entry->lastDateAsn1.length > 0 && entry->lastDateFormat == 0) {
            XMEMCPY(entry->lastDate, entry->lastDateAsn1.data,
                    (size_t)entry->lastDateAsn1.length);
            entry->lastDateFormat = (byte)entry->lastDateAsn1.type;
        }
        if (entry->nextDateAsn1.length > 0 && entry->nextDateFormat == 0) {
            XMEMCPY(entry->nextDate, entry->nextDateAsn1.data,
                    (size_t)entry->nextDateAsn1.length);
            entry->nextDateFormat = (byte)entry->nextDateAsn1.type;
        }
    }

    /* Verify we have valid dates */
    if (ret == WOLFSSL_SUCCESS) {
        if (entry->lastDateFormat == 0) {
            WOLFSSL_MSG("CRL has no lastUpdate date set");
            ret = BAD_FUNC_ARG;
        }
    }

    /* Initialize RNG */
    if (ret == WOLFSSL_SUCCESS) {
        if (wc_InitRng(&rng) != 0) {
            WOLFSSL_MSG("RNG init failed");
            ret = WOLFSSL_FAILURE;
        }
        else {
            rngInit = 1;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        const byte* crlNumber = NULL;
        word32 crlNumberSz = 0;

        if (entry->crlNumberSet) {
            crlNumber = (const byte*)entry->crlNumber;
            crlNumberSz = CRL_MAX_NUM_SZ;
        }

        /* Determine TBS size, but this does not include the outer signature
         * wrapper (AlgorithmIdentifier,  BIT STRING and outer SEQUENCE) */
        bufSz = wc_MakeCRL_ex(issuerDer, (word32)issuerSz,
                              entry->lastDate, entry->lastDateFormat,
                              entry->nextDate, entry->nextDateFormat,
                              entry->certs, crlNumber, crlNumberSz,
                              sigType, entry->version, NULL, 0);
        if (bufSz < 0) {
            WOLFSSL_MSG("wc_MakeCRL_ex size check failed");
            ret = bufSz;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        bufSz = GetCrlSignBufSz(bufSz, sigType, rsaKey, eccKey);
        if (bufSz <= 0) {
            WOLFSSL_MSG("CRL buffer size calc failed");
            ret = bufSz;
        }
    }

    /* Allocate working buffer for TBS + signature */
    if (ret == WOLFSSL_SUCCESS) {
        buf = (byte*)XMALLOC(bufSz, crl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (buf == NULL) {
            ret = MEMORY_E;
        }
    }

    /* Build to-be-signed (TBS) portion of the CRL buffer.
     * Note that we pass the fields rather than the CRL_entry struct so
     * wolfcrypt need not know about the openSSL-compatible CRL_entry struct.
     */
    if (ret == WOLFSSL_SUCCESS) {
        const byte* crlNumber = NULL;
        word32 crlNumberSz = 0;

        if (entry->crlNumberSet) {
            crlNumber = (const byte*)entry->crlNumber;
            crlNumberSz = CRL_MAX_NUM_SZ;
        }

        tbsSz = wc_MakeCRL_ex(issuerDer, (word32)issuerSz,
                              entry->lastDate, entry->lastDateFormat,
                              entry->nextDate, entry->nextDateFormat,
                              entry->certs, crlNumber, crlNumberSz,
                              sigType,
                              entry->version, buf, bufSz);
        if (tbsSz < 0) {
            WOLFSSL_MSG("wc_MakeCRL_ex failed");
            ret = tbsSz;
        }
    }

    /* Sign and complete CRL. Note that the output buffer is the same as the
     * input buffer. The signature is added to the end of the buffer.
     */
    if (ret == WOLFSSL_SUCCESS) {
        totalSz = wc_SignCRL_ex(buf, tbsSz, sigType, buf, bufSz,
                                rsaKey, eccKey, &rng);
        if (totalSz < 0) {
            WOLFSSL_MSG("wc_SignCRL_ex failed");
            ret = totalSz;
        }
    }

    /* Update CRL entry with new toBeSigned and signature. Build the new
     * buffers first and only commit to entry on full success. */
    if (ret == WOLFSSL_SUCCESS) {
        byte* newToBeSigned = NULL;
        byte* newSignature = NULL;
        word32 newTbsSz = 0;
        word32 newSignatureSz = 0;
        word32 newSignatureOid = 0;

        /* Extract TBS and signature from the complete CRL buffer.
         * After AddSignature, the buffer layout is:
         * [outer SEQUENCE header][TBS][AlgorithmIdentifier][BIT STRING sig]
         */
        {
            word32 idx = 0;
            int len;
            word32 tbsStart = 0;
            word32 tbsLen = 0;
            int sigLen;

            /* Parse outer SEQUENCE */
            if (GetSequence(buf, &idx, &len, (word32)totalSz) < 0) {
                ret = ASN_PARSE_E;
            }

            /* TBS starts here */
            if (ret == WOLFSSL_SUCCESS) {
                tbsStart = idx;
            }

            /* Parse TBS SEQUENCE to get its length */
            if (ret == WOLFSSL_SUCCESS) {
                if (GetSequence(buf, &idx, &len, (word32)totalSz) < 0) {
                    ret = ASN_PARSE_E;
                }
            }
            if (ret == WOLFSSL_SUCCESS) {
                tbsLen = idx + (word32)len - tbsStart;
                idx = tbsStart + tbsLen; /* Move past TBS */
            }

            /* Allocate and copy TBS */
            if (ret == WOLFSSL_SUCCESS) {
                newToBeSigned = (byte*)XMALLOC(tbsLen, crl->heap,
                                               DYNAMIC_TYPE_CRL_ENTRY);
                if (newToBeSigned == NULL) {
                    ret = MEMORY_E;
                }
            }
            if (ret == WOLFSSL_SUCCESS) {
                XMEMCPY(newToBeSigned, buf + tbsStart, tbsLen);
                newTbsSz = tbsLen;
            }

            /* Skip AlgorithmIdentifier */
            if (ret == WOLFSSL_SUCCESS) {
                if (GetAlgoId(buf, &idx, (word32*)&len, oidSigType,
                        (word32)totalSz) < 0) {
                    ret = ASN_PARSE_E;
                }
            }

            /* Get BIT STRING */
            if (ret == WOLFSSL_SUCCESS) {
                if (GetASNHeader(buf, ASN_BIT_STRING, &idx, &sigLen,
                        (word32)totalSz) < 0) {
                    ret = ASN_PARSE_E;
                }
            }

            /* Skip unused bits byte */
            if (ret == WOLFSSL_SUCCESS) {
                if (idx >= (word32)totalSz || sigLen <= 0 || buf[idx] != 0) {
                    ret = ASN_PARSE_E;
                }
            }
            if (ret == WOLFSSL_SUCCESS) {
                idx++;
                sigLen--;
            }

            if (ret == WOLFSSL_SUCCESS) {
                newSignature = (byte*)XMALLOC((word32)sigLen, crl->heap,
                                              DYNAMIC_TYPE_CRL_ENTRY);
                if (newSignature == NULL) {
                    ret = MEMORY_E;
                }
            }
            if (ret == WOLFSSL_SUCCESS) {
                XMEMCPY(newSignature, buf + idx, (size_t)sigLen);
                newSignatureSz = (word32)sigLen;
                newSignatureOid = (word32)sigType;
            }
        }

        if (ret == WOLFSSL_SUCCESS) {
            if (entry->toBeSigned != NULL) {
                XFREE(entry->toBeSigned, crl->heap, DYNAMIC_TYPE_CRL_ENTRY);
                entry->toBeSigned = NULL;
            }
            if (entry->signature != NULL) {
                XFREE(entry->signature, crl->heap, DYNAMIC_TYPE_CRL_ENTRY);
                entry->signature = NULL;
            }

            entry->toBeSigned = newToBeSigned;
            entry->tbsSz = newTbsSz;
            entry->signature = newSignature;
            entry->signatureSz = newSignatureSz;
            entry->signatureOID = newSignatureOid;
        }
        else {
            if (newToBeSigned != NULL) {
                XFREE(newToBeSigned, crl->heap, DYNAMIC_TYPE_CRL_ENTRY);
            }
            if (newSignature != NULL) {
                XFREE(newSignature, crl->heap, DYNAMIC_TYPE_CRL_ENTRY);
            }
        }
    }

    /* Mark the CRL as verified/signed for future reference. */
    if (ret == WOLFSSL_SUCCESS) {
        entry->verified = 1;
    }

    if (issuerDer) {
        XFREE(issuerDer, crl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (buf) {
        XFREE(buf, crl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (rngInit) {
        wc_FreeRng(&rng);
    }

    return ret;
}
#endif /* WOLFSSL_CERT_GEN */

#endif /* OPENSSL_EXTRA */

#endif /* HAVE_CRL */
#endif /* !WOLFCRYPT_ONLY */
