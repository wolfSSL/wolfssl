/* libfcs_stub.c
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

#include <errno.h>
#include "libfcs.h"

#define FCS_STUB_UNUSED(x) (void)(x)

FCS_OSAL_INT libfcs_init(FCS_OSAL_CHAR* loglevel)
{
    FCS_STUB_UNUSED(loglevel);
    return 0;
}

FCS_OSAL_INT fcs_open_service_session(FCS_OSAL_UUID* sessionId)
{
    FCS_STUB_UNUSED(sessionId);
    return -ENXIO;
}

FCS_OSAL_INT fcs_close_service_session(FCS_OSAL_UUID* sessionId)
{
    FCS_STUB_UNUSED(sessionId);
    return 0;
}

FCS_OSAL_INT fcs_random_number_ext(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 contextId, FCS_OSAL_CHAR* rng, FCS_OSAL_U32 rngSz)
{
    FCS_STUB_UNUSED(sessionId);
    FCS_STUB_UNUSED(contextId);
    FCS_STUB_UNUSED(rng);
    FCS_STUB_UNUSED(rngSz);
    return -ENOTSUP;
}

FCS_OSAL_INT fcs_import_service_key(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_CHAR* key, FCS_OSAL_INT keySz, FCS_OSAL_CHAR* status,
    FCS_OSAL_UINT* statusSz)
{
    FCS_STUB_UNUSED(sessionId);
    FCS_STUB_UNUSED(key);
    FCS_STUB_UNUSED(keySz);
    FCS_STUB_UNUSED(status);
    FCS_STUB_UNUSED(statusSz);
    return -ENOTSUP;
}

FCS_OSAL_INT fcs_create_service_key(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_CHAR* key, FCS_OSAL_INT keySz, FCS_OSAL_CHAR* status,
    FCS_OSAL_UINT statusSz)
{
    FCS_STUB_UNUSED(sessionId);
    FCS_STUB_UNUSED(key);
    FCS_STUB_UNUSED(keySz);
    FCS_STUB_UNUSED(status);
    FCS_STUB_UNUSED(statusSz);
    return -ENOTSUP;
}

FCS_OSAL_INT fcs_remove_service_key(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 keyId)
{
    FCS_STUB_UNUSED(sessionId);
    FCS_STUB_UNUSED(keyId);
    return -ENOTSUP;
}

FCS_OSAL_INT fcs_get_digest(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 contextId, FCS_OSAL_U32 keyId,
    struct fcs_digest_get_req* req)
{
    FCS_STUB_UNUSED(sessionId);
    FCS_STUB_UNUSED(contextId);
    FCS_STUB_UNUSED(keyId);
    FCS_STUB_UNUSED(req);
    return -ENOTSUP;
}

FCS_OSAL_INT fcs_aes_crypt(FCS_OSAL_UUID* sessionId, FCS_OSAL_U32 keyId,
    FCS_OSAL_U32 contextId, struct fcs_aes_req* req)
{
    FCS_STUB_UNUSED(sessionId);
    FCS_STUB_UNUSED(keyId);
    FCS_STUB_UNUSED(contextId);
    FCS_STUB_UNUSED(req);
    return -ENOTSUP;
}

FCS_OSAL_INT fcs_ecdsa_get_pub_key(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 contextId, FCS_OSAL_U32 keyId, FCS_OSAL_U32 curve,
    FCS_OSAL_CHAR* publicKey, FCS_OSAL_U32* publicKeySz)
{
    FCS_STUB_UNUSED(sessionId);
    FCS_STUB_UNUSED(contextId);
    FCS_STUB_UNUSED(keyId);
    FCS_STUB_UNUSED(curve);
    FCS_STUB_UNUSED(publicKey);
    FCS_STUB_UNUSED(publicKeySz);
    return -ENOTSUP;
}

FCS_OSAL_INT fcs_ecdsa_hash_sign(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 contextId, FCS_OSAL_U32 keyId,
    struct fcs_ecdsa_req* req)
{
    FCS_STUB_UNUSED(sessionId);
    FCS_STUB_UNUSED(contextId);
    FCS_STUB_UNUSED(keyId);
    FCS_STUB_UNUSED(req);
    return -ENOTSUP;
}

FCS_OSAL_INT fcs_ecdh_request(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 keyId, FCS_OSAL_U32 contextId, struct fcs_ecdh_req* req)
{
    FCS_STUB_UNUSED(sessionId);
    FCS_STUB_UNUSED(keyId);
    FCS_STUB_UNUSED(contextId);
    FCS_STUB_UNUSED(req);
    return -ENOTSUP;
}

FCS_OSAL_INT fcs_mac_verify(FCS_OSAL_UUID* sessionId,
    FCS_OSAL_U32 contextId, FCS_OSAL_U32 keyId,
    struct fcs_mac_verify_req* req)
{
    FCS_STUB_UNUSED(sessionId);
    FCS_STUB_UNUSED(contextId);
    FCS_STUB_UNUSED(keyId);
    FCS_STUB_UNUSED(req);
    return -ENOTSUP;
}
