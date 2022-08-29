/* dtls.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

#if defined(WOLFSSL_DTLS_CID)

#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>

typedef struct ConnectionID {
    byte length;
    byte id[];
} ConnectionID;

typedef struct CIDInfo {
    ConnectionID* tx;
    ConnectionID* rx;
    byte negotiated : 1;
} CIDInfo;

static ConnectionID* DtlsCidNew(const byte* cid, byte size, void* heap)
{
    ConnectionID* ret;

    ret = (ConnectionID*)XMALLOC(sizeof(ConnectionID) + size, heap,
        DYNAMIC_TYPE_TLSX);
    if (ret == NULL)
        return NULL;

    ret->length = size;
    XMEMCPY(ret->id, cid, size);

    return ret;
}

static WC_INLINE CIDInfo* DtlsCidGetInfo(WOLFSSL* ssl)
{
    return ssl->dtlsCidInfo;
}

static int DtlsCidGetSize(WOLFSSL* ssl, unsigned int* size, int rx)
{
    ConnectionID* id;
    CIDInfo* info;

    if (ssl == NULL || size == NULL)
        return BAD_FUNC_ARG;

    info = DtlsCidGetInfo(ssl);
    if (info == NULL)
        return WOLFSSL_FAILURE;

    id = rx ? info->rx : info->tx;
    if (id == NULL) {
        *size = 0;
        return WOLFSSL_SUCCESS;
    }

    *size = id->length;
    return WOLFSSL_SUCCESS;
}

static int DtlsCidGet(WOLFSSL* ssl, unsigned char* buf, int bufferSz, int rx)
{
    ConnectionID* id;
    CIDInfo* info;

    if (ssl == NULL || buf == NULL)
        return BAD_FUNC_ARG;

    info = DtlsCidGetInfo(ssl);
    if (info == NULL)
        return WOLFSSL_FAILURE;

    id = rx ? info->rx : info->tx;
    if (id == NULL || id->length == 0)
        return WOLFSSL_SUCCESS;

    if (id->length > bufferSz)
        return LENGTH_ERROR;

    XMEMCPY(buf, id->id, id->length);
    return WOLFSSL_SUCCESS;
}

static CIDInfo* DtlsCidGetInfoFromExt(byte* ext)
{
    WOLFSSL** sslPtr;
    WOLFSSL* ssl;

    if (ext == NULL)
        return NULL;
    sslPtr = (WOLFSSL**)ext;
    ssl = *sslPtr;
    if (ssl == NULL)
        return NULL;
    return ssl->dtlsCidInfo;
}

static void DtlsCidUnsetInfoFromExt(byte* ext)
{
    WOLFSSL** sslPtr;
    WOLFSSL* ssl;

    if (ext == NULL)
        return;
    sslPtr = (WOLFSSL**)ext;
    ssl = *sslPtr;
    if (ssl == NULL)
        return;
    ssl->dtlsCidInfo = NULL;
}

void TLSX_ConnectionID_Free(byte* ext, void* heap)
{
    CIDInfo* info;
    (void)heap;

    info = DtlsCidGetInfoFromExt(ext);
    if (info == NULL)
        return;
    if (info->rx != NULL)
        XFREE(info->rx, heap, DYNAMIC_TYPE_TLSX);
    if (info->tx != NULL)
        XFREE(info->tx, heap, DYNAMIC_TYPE_TLSX);
    XFREE(info, heap, DYNAMIC_TYPE_TLSX);
    DtlsCidUnsetInfoFromExt(ext);
    XFREE(ext, heap, DYNAMIC_TYPE_TLSX);
}

word16 TLSX_ConnectionID_Write(byte* ext, byte* output)
{
    CIDInfo* info;

    info = DtlsCidGetInfoFromExt(ext);
    if (info == NULL)
        return 0;

    /* empty CID */
    if (info->rx == NULL) {
        *output = 0;
        return OPAQUE8_LEN;
    }

    *output = info->rx->length;
    XMEMCPY(output + OPAQUE8_LEN, info->rx->id, info->rx->length);
    return OPAQUE8_LEN + info->rx->length;
}

word16 TLSX_ConnectionID_GetSize(byte* ext)
{
    CIDInfo* info = DtlsCidGetInfoFromExt(ext);
    if (info == NULL)
        return 0;
    return info->rx == NULL ? OPAQUE8_LEN : OPAQUE8_LEN + info->rx->length;
}

int TLSX_ConnectionID_Use(WOLFSSL* ssl)
{
    CIDInfo* info;
    WOLFSSL** ext;
    int ret;

    ext = (WOLFSSL**)TLSX_Find(ssl->extensions, TLSX_CONNECTION_ID);
    if (ext != NULL)
        return 0;

    info = (CIDInfo*)XMALLOC(sizeof(CIDInfo), ssl->heap, DYNAMIC_TYPE_TLSX);
    if (info == NULL)
        return MEMORY_ERROR;
    ext = (WOLFSSL**)XMALLOC(sizeof(WOLFSSL**), ssl->heap, DYNAMIC_TYPE_TLSX);
    if (ext == NULL) {
        XFREE(info, ssl->heap, DYNAMIC_TYPE_TLSX);
        return MEMORY_ERROR;
    }
    XMEMSET(info, 0, sizeof(CIDInfo));
    /* CIDInfo needs to be accessed every time we send or receive a record. To
     * avoid the cost of the extension lookup save a pointer to the structure
     * inside the SSL object itself, and save a pointer to the SSL object in the
     * extension. The extension freeing routine uses te pointer to the SSL
     * object to find the structure and to set ssl->dtlsCidInfo pointer to NULL
     * after freeing the structure. */
    ssl->dtlsCidInfo = info;
    *ext = ssl;
    ret =
        TLSX_Push(&ssl->extensions, TLSX_CONNECTION_ID, (void*)ext, ssl->heap);
    if (ret != 0) {
        XFREE(info, ssl->heap, DYNAMIC_TYPE_TLSX);
        XFREE(ext, ssl->heap, DYNAMIC_TYPE_TLSX);
        ssl->dtlsCidInfo = NULL;
        return ret;
    }

    return 0;
}

int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,
    byte isRequest)
{
    ConnectionID* id;
    CIDInfo* info;
    byte cidSize;
    TLSX* ext;

    ext = TLSX_Find(ssl->extensions, TLSX_CONNECTION_ID);
    if (ext == NULL) {
        /* CID not enabled */
        if (isRequest) {
            WOLFSSL_MSG("Received CID ext but it's not enabled, ignoring");
            return 0;
        }
        else {
            WOLFSSL_MSG("CID ext not requested by the Client, aborting");
            return UNSUPPORTED_EXTENSION;
        }
    }

    info = DtlsCidGetInfo(ssl);
    if (info == NULL || info->tx != NULL)
        return BAD_STATE_E;

    if (length < OPAQUE8_LEN)
        return BUFFER_ERROR;

    cidSize = *input;
    if (cidSize + OPAQUE8_LEN > length)
        return BUFFER_ERROR;

    if (cidSize > 0) {
        id = (ConnectionID*)XMALLOC(sizeof(*id) + cidSize, ssl->heap,
            DYNAMIC_TYPE_TLSX);
        if (id == NULL)
            return MEMORY_ERROR;
        XMEMCPY(id->id, input + OPAQUE8_LEN, cidSize);
        id->length = cidSize;
        info->tx = id;
    }

    info->negotiated = 1;
    if (isRequest)
        ext->resp = 1;

    return 0;
}

void DtlsCIDOnExtensionsParsed(WOLFSSL* ssl)
{
    CIDInfo* info;

    info = DtlsCidGetInfo(ssl);
    if (info == NULL)
        return;

    if (!info->negotiated) {
        TLSX_Remove(&ssl->extensions, TLSX_CONNECTION_ID, ssl->heap);
        return;
    }
}

byte DtlsCIDCheck(WOLFSSL* ssl, const byte* input, word16 inputSize)
{
    CIDInfo* info;
    info = DtlsCidGetInfo(ssl);
    if (info == NULL || info->rx == NULL || info->rx->length == 0)
        return 0;
    if (inputSize < info->rx->length)
        return 0;
    return XMEMCMP(input, info->rx->id, info->rx->length) == 0;
}

int wolfSSL_dtls_cid_use(WOLFSSL* ssl)
{
    int ret;

    /* CID is supported on DTLSv1.3 only */
    if (!IsAtLeastTLSv1_3(ssl->version))
        return WOLFSSL_FAILURE;

    ssl->options.useDtlsCID = 1;
    ret = TLSX_ConnectionID_Use(ssl);
    if (ret != 0)
        return ret;
    return WOLFSSL_SUCCESS;
}

int wolfSSL_dtls_cid_is_enabled(WOLFSSL* ssl)
{
    return DtlsCidGetInfo(ssl) != NULL;
}

int wolfSSL_dtls_cid_set(WOLFSSL* ssl, unsigned char* cid, unsigned int size)
{
    ConnectionID* newCid;
    CIDInfo* cidInfo;

    if (!ssl->options.useDtlsCID)
        return WOLFSSL_FAILURE;

    cidInfo = DtlsCidGetInfo(ssl);
    if (cidInfo == NULL)
        return WOLFSSL_FAILURE;

    if (cidInfo->rx != NULL) {
        XFREE(cidInfo->rx, ssl->heap, DYNAMIC_TYPE_TLSX);
        cidInfo->rx = NULL;
    }

    /* empty CID */
    if (size == 0)
        return WOLFSSL_SUCCESS;

    if (size > DTLS_CID_MAX_SIZE)
        return LENGTH_ERROR;

    newCid = DtlsCidNew(cid, (byte)size, ssl->heap);
    if (newCid == NULL)
        return MEMORY_ERROR;
    cidInfo->rx = newCid;
    return WOLFSSL_SUCCESS;
}

int wolfSSL_dtls_cid_get_rx_size(WOLFSSL* ssl, unsigned int* size)
{
    return DtlsCidGetSize(ssl, size, 1);
}

int wolfSSL_dtls_cid_get_rx(WOLFSSL* ssl, unsigned char* buf,
    unsigned int bufferSz)
{
    return DtlsCidGet(ssl, buf, bufferSz, 1);
}

int wolfSSL_dtls_cid_get_tx_size(WOLFSSL* ssl, unsigned int* size)
{
    return DtlsCidGetSize(ssl, size, 0);
}

int wolfSSL_dtls_cid_get_tx(WOLFSSL* ssl, unsigned char* buf,
    unsigned int bufferSz)
{
    return DtlsCidGet(ssl, buf, bufferSz, 0);
}

#endif /* WOLFSSL_DTLS_CID */
