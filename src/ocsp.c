/* ocsp.c
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ctaocrypt/settings.h>

#ifdef HAVE_OCSP

#include <cyassl/error.h>
#include <cyassl/ocsp.h>
#include <cyassl/internal.h>


int InitOCSP(CYASSL_OCSP* ocsp, CYASSL_CERT_MANAGER* cm)
{
    CYASSL_ENTER("InitOCSP");
    XMEMSET(ocsp, 0, sizeof(*ocsp));
    ocsp->cm = cm;

    return 0;
}


static int InitOCSP_Entry(OCSP_Entry* ocspe, DecodedCert* cert)
{
    CYASSL_ENTER("InitOCSP_Entry");

    ocspe->next = NULL;
    XMEMCPY(ocspe->issuerHash, cert->issuerHash, SHA_DIGEST_SIZE);
    XMEMCPY(ocspe->issuerKeyHash, cert->issuerKeyHash, SHA_DIGEST_SIZE);
    ocspe->status = NULL;
    ocspe->totalStatus = 0;

    return 0;
}


static void FreeOCSP_Entry(OCSP_Entry* ocspe)
{
    CertStatus* tmp = ocspe->status;

    CYASSL_ENTER("FreeOCSP_Entry");

    while (tmp) {
        CertStatus* next = tmp->next;
        XFREE(tmp, NULL, DYNAMIC_TYPE_OCSP_STATUS);
        tmp = next;
    }
}


void FreeOCSP(CYASSL_OCSP* ocsp, int dynamic)
{
    OCSP_Entry* tmp = ocsp->ocspList;

    CYASSL_ENTER("FreeOCSP");

    while (tmp) {
        OCSP_Entry* next = tmp->next;
        FreeOCSP_Entry(tmp);
        XFREE(tmp, NULL, DYNAMIC_TYPE_OCSP_ENTRY);
        tmp = next;
    }

    if (dynamic)
        XFREE(ocsp, NULL, DYNAMIC_TYPE_OCSP);
}


static OCSP_Entry* find_ocsp_entry(CYASSL_OCSP* ocsp, DecodedCert* cert)
{
    OCSP_Entry* entry = ocsp->ocspList;

    while (entry)
    {
        if (XMEMCMP(entry->issuerHash, cert->issuerHash, SHA_DIGEST_SIZE) == 0
            && XMEMCMP(entry->issuerKeyHash, cert->issuerKeyHash,
                                                        SHA_DIGEST_SIZE) == 0)
        {
            CYASSL_MSG("Found OCSP responder");
            break;
        }
        else
        {
            entry = entry->next;
        }
    }

    if (entry == NULL)
    {
        CYASSL_MSG("Add a new OCSP entry");
        entry = (OCSP_Entry*)XMALLOC(sizeof(OCSP_Entry),
                                                NULL, DYNAMIC_TYPE_OCSP_ENTRY);
        if (entry != NULL)
        {
            InitOCSP_Entry(entry, cert);
            entry->next = ocsp->ocspList;
            ocsp->ocspList = entry;
        }
    }

    return entry;
}


static CertStatus* find_cert_status(OCSP_Entry* ocspe, DecodedCert* cert)
{
    CertStatus* stat = ocspe->status;

    while (stat)
    {
        if(stat->serialSz == cert->serialSz &&
            (XMEMCMP(stat->serial, cert->serial, cert->serialSz) == 0))
        {
            break;
        }
        else
        {
            stat = stat->next;
        }
    }
    if (stat == NULL)
    {
        stat = (CertStatus*)XMALLOC(sizeof(CertStatus),
                                            NULL, DYNAMIC_TYPE_OCSP_STATUS);
        if (stat != NULL)
        {
            XMEMCPY(stat->serial, cert->serial, cert->serialSz);
            stat->serialSz = cert->serialSz;
            stat->status = -1;
            stat->nextDate[0] = 0;
            ocspe->totalStatus++;

            stat->next = ocspe->status;
            ocspe->status = stat;
        }
    }

    return stat;
}


static int xstat2err(int stat)
{
    switch (stat) {
        case CERT_GOOD:
            return 0;
            break;
        case CERT_REVOKED:
            return OCSP_CERT_REVOKED;
            break;
        default:
            return OCSP_CERT_UNKNOWN;
            break;
    }
}


int CheckCertOCSP(CYASSL_OCSP* ocsp, DecodedCert* cert)
{
    byte* ocspReqBuf = NULL;
    int ocspReqSz = 2048;
    byte* ocspRespBuf = NULL;
    OcspRequest ocspRequest;
    OcspResponse ocspResponse;
    int result = 0;
    OCSP_Entry* ocspe;
    CertStatus* certStatus;
    const char *url;
    int urlSz;

    CYASSL_ENTER("CheckCertOCSP");

    ocspe = find_ocsp_entry(ocsp, cert);
    if (ocspe == NULL) {
        CYASSL_MSG("alloc OCSP entry failed");
        return MEMORY_ERROR;
    }

    certStatus = find_cert_status(ocspe, cert);
    if (certStatus == NULL)
    {
        CYASSL_MSG("alloc OCSP cert status failed");
        return MEMORY_ERROR;
    }

    if (certStatus->status != -1)
    {
        if (!ValidateDate(certStatus->thisDate,
                                        certStatus->thisDateFormat, BEFORE) ||
            (certStatus->nextDate[0] == 0) ||
            !ValidateDate(certStatus->nextDate,
                                        certStatus->nextDateFormat, AFTER))
        {
            CYASSL_MSG("\tinvalid status date, looking up cert");
            certStatus->status = -1;
        }
        else
        {
            CYASSL_MSG("\tusing cached status");
            result = xstat2err(certStatus->status);
            return result;
        }
    }

    if (ocsp->cm->ocspUseOverrideURL) {
        url = ocsp->cm->ocspOverrideURL;
        if (url != NULL && url[0] != '\0')
            urlSz = (int)XSTRLEN(url);
        else
            return OCSP_NEED_URL;
    }
    else if (cert->extAuthInfoSz != 0 && cert->extAuthInfo != NULL) {
        url = (const char *)cert->extAuthInfo;
        urlSz = cert->extAuthInfoSz;
    }
    else {
        CYASSL_MSG("\tcert doesn't have extAuthInfo, assuming CERT_GOOD");
        return 0;
    }

    ocspReqBuf = (byte*)XMALLOC(ocspReqSz, NULL, DYNAMIC_TYPE_IN_BUFFER);
    if (ocspReqBuf == NULL) {
        CYASSL_MSG("\talloc OCSP request buffer failed");
        return MEMORY_ERROR;
    }
    InitOcspRequest(&ocspRequest, cert, ocsp->cm->ocspSendNonce,
                                                         ocspReqBuf, ocspReqSz);
    ocspReqSz = EncodeOcspRequest(&ocspRequest);
    
    if (ocsp->cm->ocspIOCb) {
        result = ocsp->cm->ocspIOCb(ocsp->cm->ocspIOCtx, url, urlSz,
                                          ocspReqBuf, ocspReqSz, &ocspRespBuf);
    }

    if (result >= 0 && ocspRespBuf) {
        InitOcspResponse(&ocspResponse, certStatus, ocspRespBuf, result);
        OcspResponseDecode(&ocspResponse);
    
        if (ocspResponse.responseStatus != OCSP_SUCCESSFUL) {
            CYASSL_MSG("OCSP Responder failure");
            result = OCSP_LOOKUP_FAIL;
        } else {
            if (CompareOcspReqResp(&ocspRequest, &ocspResponse) == 0)
            {
                result = xstat2err(ocspResponse.status->status);
            }
            else
            {
                CYASSL_MSG("OCSP Response incorrect for Request");
                result = OCSP_LOOKUP_FAIL;
            }
        }
    }
    else {
        result = OCSP_LOOKUP_FAIL;
    }

    if (ocspReqBuf != NULL) {
        XFREE(ocspReqBuf, NULL, DYNAMIC_TYPE_IN_BUFFER);
    }
    if (ocspRespBuf != NULL && ocsp->cm->ocspRespFreeCb) {
        ocsp->cm->ocspRespFreeCb(ocsp->cm->ocspIOCtx, ocspRespBuf);
    }

    return result;
}


#endif /* HAVE_OCSP */

