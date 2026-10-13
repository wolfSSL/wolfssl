/* cryif.c
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

/* AutoSAR 4.4 */
/* shim layer for use of wolfSSL crypto driver */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_AUTOSAR
#ifndef NO_WOLFSSL_AUTOSAR_CRYIF

#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/port/autosar/Csm.h>
#include <wolfssl/wolfcrypt/port/autosar/CryIf.h>
#include <wolfssl/wolfcrypt/port/autosar/Crypto.h>


#include <wolfssl/wolfcrypt/logging.h>

/* initialization function */
void CryIf_Init(const CryIf_ConfigType* in)
{
    Crypto_ConfigType cryptoConfig;

    if (in != NULL) {
        cryptoConfig.heap  = in->heap;
        cryptoConfig.devId = in->devId;
    }
    else {
        cryptoConfig.heap  = NULL;
        cryptoConfig.devId = WOLFSSL_AUTOSAR_DEVID;
    }

    Crypto_Init(&cryptoConfig);
}


void CryIf_GetVersionInfo(Std_VersionInfoType* ver)
{
    if (ver != NULL) {
        ver->vendorID = 0; /* no vendor or module ID */
        ver->moduleID = 0;
        ver->sw_major_version = (LIBWOLFSSL_VERSION_HEX >> 24) & 0xFFF;
        ver->sw_minor_version = (LIBWOLFSSL_VERSION_HEX >> 12) & 0xFFF;
        ver->sw_patch_version = (LIBWOLFSSL_VERSION_HEX) & 0xFFF;
    }
}


/* returns E_OK on success */
Std_ReturnType CryIf_ProcessJob(uint32 id, Crypto_JobType* job)
{
    WOLFSSL_ENTER("CryIf_ProcessJob");
    if (job == NULL) {
        return E_NOT_OK;
    }

    /* only handle synchronous jobs */
    if (job->jobPrimitiveInfo->processingType != CRYPTO_PROCESSING_SYNC) {
        WOLFSSL_MSG("Crypto Interface only supporting synchronous jobs");
        return E_NOT_OK;
    }

    return Crypto_ProcessJob(id, job);
}


/* Passes a cancel down to the driver, which releases the job's slot.
 *
 * There is nothing queued at this layer to withdraw -- every job is
 * synchronous, so one is either running in the caller's own thread or has
 * already returned -- which is why this does not check processingType the way
 * CryIf_ProcessJob() does.
 *
 * returns E_OK when the driver released a slot */
Std_ReturnType CryIf_CancelJob(uint32 id, Crypto_JobType* job)
{
    if (job == NULL) {
        WOLFSSL_MSG("CryIf_CancelJob called with no job");
        return E_NOT_OK;
    }

    return Crypto_CancelJob(id, job);
}


/* return E_OK on success */
Std_ReturnType CryIf_KeyElementSet(uint32 keyId, uint32 eId, const uint8* key,
        uint32 keySz)
{
    if (key == NULL || keySz == 0) {
        /* report CRYIF_E_PARAM_POINTER to the DET */
        return E_NOT_OK;
    }

    return Crypto_KeyElementSet(keyId, eId, key, keySz);
}


#ifdef WOLF_PRIVATE_KEY_ID
/* return E_OK on success */
Std_ReturnType CryIf_KeyElementSetId(uint32 keyId, uint32 eId, const uint8* id,
        uint32 idLen)
{
    if (id == NULL || idLen == 0) {
        /* report CRYIF_E_PARAM_POINTER to the DET */
        return E_NOT_OK;
    }

    return Crypto_KeyElementSetId(keyId, eId, id, idLen);
}


/* return E_OK on success */
Std_ReturnType CryIf_KeyElementSetLabel(uint32 keyId, uint32 eId,
        const char* label)
{
    if (label == NULL) {
        /* report CRYIF_E_PARAM_POINTER to the DET */
        return E_NOT_OK;
    }

    return Crypto_KeyElementSetLabel(keyId, eId, label);
}
#endif /* WOLF_PRIVATE_KEY_ID */
#endif /* NO_WOLFSSL_AUTOSAR_CRYIF */
#endif /* WOLFSSL_AUTOSAR */

