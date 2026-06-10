/* ssl_api_dtls.c
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

#if !defined(WOLFSSL_SSL_API_DTLS_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_api_dtls.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef WOLFCRYPT_ONLY

#ifdef WOLFSSL_DTLS
/* Set the file descriptor for an already connected DTLS object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] fd   Connected socket file descriptor.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_set_dtls_fd_connected(WOLFSSL* ssl, int fd)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_set_dtls_fd_connected");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_set_fd(ssl, fd);
    if (ret == WOLFSSL_SUCCESS)
        ssl->buffers.dtlsCtx.connected = 1;

    return ret;
}
#endif


/* Determine whether the object is configured for DTLS.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when using DTLS.
 * @return  0 otherwise, or when ssl is NULL.
 */
int wolfSSL_dtls(WOLFSSL* ssl)
{
    int dtlsOpt = 0;
    if (ssl)
        dtlsOpt = ssl->options.dtls;
    return dtlsOpt;
}


#ifndef WOLFSSL_LEANPSK
#if defined(WOLFSSL_DTLS) && defined(XINET_PTON) && \
    !defined(WOLFSSL_NO_SOCK) && defined(HAVE_SOCKADDR)
/* Create a DTLS peer address from a port and IPv4 address string.
 *
 * The returned object must be freed with wolfSSL_dtls_free_peer().
 *
 * @param [in] port  Port number.
 * @param [in] ip    Dotted-decimal IPv4 address string.
 * @return  Newly allocated peer address on success.
 * @return  NULL on allocation error or when the address is invalid.
 */
void* wolfSSL_dtls_create_peer(int port, char* ip)
{
    SOCKADDR_IN *addr;
    addr = (SOCKADDR_IN*)XMALLOC(sizeof(*addr), NULL,
            DYNAMIC_TYPE_SOCKADDR);
    if (addr == NULL) {
        return NULL;
    }

    addr->sin_family = AF_INET;
    addr->sin_port = XHTONS((word16)port);
    if (XINET_PTON(AF_INET, ip, &addr->sin_addr) < 1) {
        XFREE(addr, NULL, DYNAMIC_TYPE_SOCKADDR);
        return NULL;
    }

    return addr;
}

/* Free a DTLS peer address created with wolfSSL_dtls_create_peer().
 *
 * @param [in] addr  Peer address to free.
 * @return  WOLFSSL_SUCCESS always.
 */
int wolfSSL_dtls_free_peer(void* addr)
{
    XFREE(addr, NULL, DYNAMIC_TYPE_SOCKADDR);
    return WOLFSSL_SUCCESS;
}
#endif

#ifdef WOLFSSL_DTLS
/* Store a socket address into a socket address holder, resizing as needed.
 *
 * A NULL or zero-length peer frees the holder's buffer.
 *
 * @param [in, out] sockAddr  Socket address holder.
 * @param [in]      peer      Socket address data, may be NULL to free.
 * @param [in]      peerSz    Length of socket address data in bytes.
 * @param [in]      heap      Heap hint for dynamic memory allocation.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE on allocation error.
 */
static int SockAddrSet(WOLFSSL_SOCKADDR* sockAddr, void* peer,
                       unsigned int peerSz, void* heap)
{
    if (peer == NULL || peerSz == 0) {
        if (sockAddr->sa != NULL)
            XFREE(sockAddr->sa, heap, DYNAMIC_TYPE_SOCKADDR);
        sockAddr->sa = NULL;
        sockAddr->sz = 0;
        sockAddr->bufSz = 0;
        return WOLFSSL_SUCCESS;
    }

    if (peerSz > sockAddr->bufSz) {
        if (sockAddr->sa != NULL)
            XFREE(sockAddr->sa, heap, DYNAMIC_TYPE_SOCKADDR);
        sockAddr->sa =
                (void*)XMALLOC(peerSz, heap, DYNAMIC_TYPE_SOCKADDR);
        if (sockAddr->sa == NULL) {
            sockAddr->sz = 0;
            sockAddr->bufSz = 0;
            return WOLFSSL_FAILURE;
        }
        sockAddr->bufSz = peerSz;
    }
    XMEMCPY(sockAddr->sa, peer, peerSz);
    sockAddr->sz = peerSz;
    return WOLFSSL_SUCCESS;
}
#endif

/* Set the DTLS peer address on the object.
 *
 * @param [in] ssl     SSL/TLS object.
 * @param [in] peer    Peer socket address, may be NULL to clear.
 * @param [in] peerSz  Length of peer address in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl is NULL or on error.
 * @return  WOLFSSL_NOT_IMPLEMENTED when DTLS is not compiled in.
 */
int wolfSSL_dtls_set_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz)
{
#ifdef WOLFSSL_DTLS
    int ret;

    if (ssl == NULL)
        return WOLFSSL_FAILURE;
#ifdef WOLFSSL_RW_THREADED
    if (wc_LockRwLock_Wr(&ssl->buffers.dtlsCtx.peerLock) != 0)
        return WOLFSSL_FAILURE;
#endif
    ret = SockAddrSet(&ssl->buffers.dtlsCtx.peer, peer, peerSz, ssl->heap);
    if (ret == WOLFSSL_SUCCESS && !(peer == NULL || peerSz == 0))
        ssl->buffers.dtlsCtx.userSet = 1;
    else
        ssl->buffers.dtlsCtx.userSet = 0;
#ifdef WOLFSSL_RW_THREADED
    if (wc_UnLockRwLock(&ssl->buffers.dtlsCtx.peerLock) != 0)
        ret = WOLFSSL_FAILURE;
#endif
    return ret;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return WOLFSSL_NOT_IMPLEMENTED;
#endif
}

#if defined(WOLFSSL_DTLS_CID) && !defined(WOLFSSL_NO_SOCK)
/* Set the pending DTLS peer address on the object.
 *
 * Used with connection ID to stage a change of peer address.
 *
 * @param [in] ssl     SSL/TLS object.
 * @param [in] peer    Peer socket address.
 * @param [in] peerSz  Length of peer address in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl is NULL or on error.
 * @return  WOLFSSL_NOT_IMPLEMENTED when DTLS is not compiled in.
 */
int wolfSSL_dtls_set_pending_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz)
{
#ifdef WOLFSSL_DTLS
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);

    if (ssl == NULL)
        return WOLFSSL_FAILURE;
#ifdef WOLFSSL_RW_THREADED
    if (wc_LockRwLock_Rd(&ssl->buffers.dtlsCtx.peerLock) != 0)
        return WOLFSSL_FAILURE;
#endif
    if (ssl->buffers.dtlsCtx.peer.sa != NULL &&
            ssl->buffers.dtlsCtx.peer.sz == peerSz &&
            sockAddrEqual((SOCKADDR_S*)ssl->buffers.dtlsCtx.peer.sa,
                    (XSOCKLENT)ssl->buffers.dtlsCtx.peer.sz, (SOCKADDR_S*)peer,
                    (XSOCKLENT)peerSz)) {
        /* Already the current peer. */
        if (ssl->buffers.dtlsCtx.pendingPeer.sa != NULL) {
            /* Clear any other pendingPeer */
            XFREE(ssl->buffers.dtlsCtx.pendingPeer.sa, ssl->heap,
                  DYNAMIC_TYPE_SOCKADDR);
            ssl->buffers.dtlsCtx.pendingPeer.sa = NULL;
            ssl->buffers.dtlsCtx.pendingPeer.sz = 0;
            ssl->buffers.dtlsCtx.pendingPeer.bufSz = 0;
        }
        ret = WOLFSSL_SUCCESS;
    }
    else {
        ret = SockAddrSet(&ssl->buffers.dtlsCtx.pendingPeer, peer, peerSz,
                ssl->heap);
    }
    if (ret == WOLFSSL_SUCCESS)
        ssl->buffers.dtlsCtx.processingPendingRecord = 0;
#ifdef WOLFSSL_RW_THREADED
    if (wc_UnLockRwLock(&ssl->buffers.dtlsCtx.peerLock) != 0)
        ret = WOLFSSL_FAILURE;
#endif
    return ret;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return WOLFSSL_NOT_IMPLEMENTED;
#endif
}
#endif /* WOLFSSL_DTLS_CID && !WOLFSSL_NO_SOCK */

/* Get a copy of the DTLS peer address from the object.
 *
 * @param [in]      ssl     SSL/TLS object.
 * @param [out]     peer    Buffer to hold the peer address.
 * @param [in, out] peerSz  In: size of buffer. Out: length of address.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl is NULL or the buffer is too small.
 * @return  WOLFSSL_NOT_IMPLEMENTED when DTLS is not compiled in.
 */
int wolfSSL_dtls_get_peer(WOLFSSL* ssl, void* peer, unsigned int* peerSz)
{
#ifdef WOLFSSL_DTLS
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ssl == NULL)
        return WOLFSSL_FAILURE;
#ifdef WOLFSSL_RW_THREADED
    if (wc_LockRwLock_Rd(&ssl->buffers.dtlsCtx.peerLock) != 0)
        return WOLFSSL_FAILURE;
#endif
    if (peer != NULL && peerSz != NULL
            && *peerSz >= ssl->buffers.dtlsCtx.peer.sz
            && ssl->buffers.dtlsCtx.peer.sa != NULL) {
        *peerSz = ssl->buffers.dtlsCtx.peer.sz;
        XMEMCPY(peer, ssl->buffers.dtlsCtx.peer.sa, *peerSz);
        ret = WOLFSSL_SUCCESS;
    }
#ifdef WOLFSSL_RW_THREADED
    if (wc_UnLockRwLock(&ssl->buffers.dtlsCtx.peerLock) != 0)
        ret = WOLFSSL_FAILURE;
#endif
    return ret;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return WOLFSSL_NOT_IMPLEMENTED;
#endif
}

/* Get a pointer to the DTLS peer address stored on the object.
 *
 * @param [in]  ssl     SSL/TLS object.
 * @param [out] peer    Pointer to the stored peer address.
 * @param [out] peerSz  Length of the peer address in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when an argument is NULL.
 * @return  WOLFSSL_NOT_IMPLEMENTED when DTLS is not compiled in or threaded.
 */
int wolfSSL_dtls_get0_peer(WOLFSSL* ssl, const void** peer,
                           unsigned int* peerSz)
{
#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_RW_THREADED)
    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    if (peer == NULL || peerSz == NULL)
        return WOLFSSL_FAILURE;

    *peer = ssl->buffers.dtlsCtx.peer.sa;
    *peerSz = ssl->buffers.dtlsCtx.peer.sz;
    return WOLFSSL_SUCCESS;
#else
    (void)ssl;
    (void)peer;
    (void)peerSz;
    return WOLFSSL_NOT_IMPLEMENTED;
#endif
}


#if defined(WOLFSSL_SCTP) && defined(WOLFSSL_DTLS)

/* Enable DTLS over SCTP mode on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_dtls_set_sctp(WOLFSSL_CTX* ctx)
{
    WOLFSSL_ENTER("wolfSSL_CTX_dtls_set_sctp");

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->dtlsSctp = 1;
    return WOLFSSL_SUCCESS;
}


/* Enable DTLS over SCTP mode on the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_dtls_set_sctp(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_dtls_set_sctp");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.dtlsSctp = 1;
    return WOLFSSL_SUCCESS;
}

#endif /* WOLFSSL_DTLS && WOLFSSL_SCTP */

#if (defined(WOLFSSL_SCTP) || defined(WOLFSSL_DTLS_MTU)) && \
                                                           defined(WOLFSSL_DTLS)

/* Set the DTLS path MTU on the context.
 *
 * @param [in] ctx     SSL/TLS context object.
 * @param [in] newMtu  Maximum transmission unit in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL or newMtu is too large.
 */
int wolfSSL_CTX_dtls_set_mtu(WOLFSSL_CTX* ctx, word16 newMtu)
{
    if (ctx == NULL || newMtu > MAX_RECORD_SIZE)
        return BAD_FUNC_ARG;

    ctx->dtlsMtuSz = newMtu;
    return WOLFSSL_SUCCESS;
}


/* Set the DTLS path MTU on the object.
 *
 * @param [in] ssl     SSL/TLS object.
 * @param [in] newMtu  Maximum transmission unit in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  WOLFSSL_FAILURE when newMtu is too large.
 */
int wolfSSL_dtls_set_mtu(WOLFSSL* ssl, word16 newMtu)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (newMtu > MAX_RECORD_SIZE) {
        ssl->error = BAD_FUNC_ARG;
        return WOLFSSL_FAILURE;
    }

    ssl->dtlsMtuSz = newMtu;
    return WOLFSSL_SUCCESS;
}

#ifdef OPENSSL_EXTRA
/* Set the DTLS path MTU on the object.
 *
 * Maps to the compatibility API SSL_set_mtu. Same as wolfSSL_dtls_set_mtu()
 * but returns only success or failure.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] mtu  Maximum transmission unit in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE on error.
 */
int wolfSSL_set_mtu_compat(WOLFSSL* ssl, unsigned short mtu)
{
    if (wolfSSL_dtls_set_mtu(ssl, mtu) == WOLFSSL_SUCCESS)
        return WOLFSSL_SUCCESS;
    else
        return WOLFSSL_FAILURE;
}
#endif /* OPENSSL_EXTRA */

#endif /* WOLFSSL_DTLS && (WOLFSSL_SCTP || WOLFSSL_DTLS_MTU) */

#ifdef WOLFSSL_SRTP

static const WOLFSSL_SRTP_PROTECTION_PROFILE gSrtpProfiles[] = {
    /* AES CCM 128, Salt:112-bits, Auth HMAC-SHA1 Tag: 80-bits
     * (master_key:128bits + master_salt:112bits) * 2 = 480 bits (60) */
    {"SRTP_AES128_CM_SHA1_80", SRTP_AES128_CM_SHA1_80,
     (((128 + 112) * 2) / 8) },
    /* AES CCM 128, Salt:112-bits, Auth HMAC-SHA1 Tag: 32-bits
     * (master_key:128bits + master_salt:112bits) * 2 = 480 bits (60) */
    {"SRTP_AES128_CM_SHA1_32", SRTP_AES128_CM_SHA1_32,
     (((128 + 112) * 2) / 8) },
    /* NULL Cipher, Salt:112-bits, Auth HMAC-SHA1 Tag 80-bits */
    {"SRTP_NULL_SHA1_80", SRTP_NULL_SHA1_80, ((112 * 2) / 8)},
    /* NULL Cipher, Salt:112-bits, Auth HMAC-SHA1 Tag 32-bits */
    {"SRTP_NULL_SHA1_32", SRTP_NULL_SHA1_32, ((112 * 2) / 8)},
    /* AES GCM 128, Salt: 96-bits, Auth GCM Tag 128-bits
     * (master_key:128bits + master_salt:96bits) * 2 = 448 bits (56) */
    {"SRTP_AEAD_AES_128_GCM", SRTP_AEAD_AES_128_GCM, (((128 + 96) * 2) / 8) },
    /* AES GCM 256, Salt: 96-bits, Auth GCM Tag 128-bits
     * (master_key:256bits + master_salt:96bits) * 2 = 704 bits (88) */
    {"SRTP_AEAD_AES_256_GCM", SRTP_AEAD_AES_256_GCM, (((256 + 96) * 2) / 8) },
};

/* Find an SRTP protection profile by name or by id.
 *
 * @param [in] profile_str      Profile name, or NULL to search by id.
 * @param [in] profile_str_len  Length of profile name in bytes.
 * @param [in] id               Profile id to search for when name is NULL.
 * @return  Matching SRTP protection profile on success.
 * @return  NULL when no profile matches.
 */
static const WOLFSSL_SRTP_PROTECTION_PROFILE* DtlsSrtpFindProfile(
    const char* profile_str, word32 profile_str_len, unsigned long id)
{
    int i;
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile = NULL;
    for (i=0;
         i<(int)(sizeof(gSrtpProfiles)/sizeof(WOLFSSL_SRTP_PROTECTION_PROFILE));
         i++) {
        if (profile_str != NULL) {
            word32 srtp_profile_len = (word32)XSTRLEN(gSrtpProfiles[i].name);
            if (srtp_profile_len == profile_str_len &&
                XMEMCMP(gSrtpProfiles[i].name, profile_str, profile_str_len)
                                                                         == 0) {
                profile = &gSrtpProfiles[i];
                break;
            }
        }
        else if (id != 0 && gSrtpProfiles[i].id == id) {
            profile = &gSrtpProfiles[i];
            break;
        }
    }
    return profile;
}

/* Select SRTP protection profiles from a colon-separated name list.
 *
 * @param [out] id           Bitmask of selected profile ids.
 * @param [in]  profile_str  Colon-separated list of SRTP profile names.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when profile_str is NULL.
 */
static int DtlsSrtpSelProfiles(word16* id, const char* profile_str)
{
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile;
    const char *current, *next = NULL;
    word32 length = 0, current_length;

    *id = 0; /* reset destination ID's */

    if (profile_str == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* loop on end of line or colon ":" */
    next = profile_str;
    length = (word32)XSTRLEN(profile_str);
    do {
        current = next;
        next = XSTRSTR(current, ":");
        if (next) {
            current_length = (word32)(next - current);
            ++next; /* ++ needed to skip ':' */
        } else {
            current_length = (word32)XSTRLEN(current);
        }
        if (current_length < length)
            length = current_length;
        profile = DtlsSrtpFindProfile(current, current_length, 0);
        if (profile != NULL) {
            *id |= (1 << profile->id); /* selected bit based on ID */
        }
    } while (next != NULL);
    return WOLFSSL_SUCCESS;
}

/* Set the SRTP protection profiles for DTLS on the context.
 *
 * @param [in] ctx          SSL/TLS context object.
 * @param [in] profile_str  Colon-separated list of SRTP profile names.
 * @return  0 on success, to match OpenSSL.
 * @return  1 on error, to match OpenSSL.
 */
int wolfSSL_CTX_set_tlsext_use_srtp(WOLFSSL_CTX* ctx, const char* profile_str)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ctx != NULL) {
        ret = DtlsSrtpSelProfiles(&ctx->dtlsSrtpProfiles, profile_str);
    }

    if (ret == WC_NO_ERR_TRACE(WOLFSSL_FAILURE)) {
        ret = 1;
    } else {
        ret = 0;
    }

    return ret;
}

/* Set the SRTP protection profiles for DTLS on the object.
 *
 * @param [in] ssl          SSL/TLS object.
 * @param [in] profile_str  Colon-separated list of SRTP profile names.
 * @return  0 on success, to match OpenSSL.
 * @return  1 on error, to match OpenSSL.
 */
int wolfSSL_set_tlsext_use_srtp(WOLFSSL* ssl, const char* profile_str)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
    if (ssl != NULL) {
        ret = DtlsSrtpSelProfiles(&ssl->dtlsSrtpProfiles, profile_str);
    }

    if (ret == WC_NO_ERR_TRACE(WOLFSSL_FAILURE)) {
        ret = 1;
    } else {
        ret = 0;
    }

    return ret;
}

/* Get the SRTP protection profile selected for the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Selected SRTP protection profile on success.
 * @return  NULL when ssl is NULL or none is selected.
 */
const WOLFSSL_SRTP_PROTECTION_PROFILE* wolfSSL_get_selected_srtp_profile(
    WOLFSSL* ssl)
{
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile = NULL;
    if (ssl) {
        profile = DtlsSrtpFindProfile(NULL, 0, ssl->dtlsSrtpId);
    }
    return profile;
}
#ifndef NO_WOLFSSL_STUB
/* Get the list of SRTP protection profiles set on the object.
 *
 * Not implemented - stub.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  NULL always.
 */
WOLF_STACK_OF(WOLFSSL_SRTP_PROTECTION_PROFILE)* wolfSSL_get_srtp_profiles(
    WOLFSSL* ssl)
{
    /* Not yet implemented - should return list of available SRTP profiles
     * ssl->dtlsSrtpProfiles */
    (void)ssl;
    return NULL;
}
#endif

#define DTLS_SRTP_KEYING_MATERIAL_LABEL "EXTRACTOR-dtls_srtp"

/* Export the DTLS-SRTP keying material for the object.
 *
 * When out is NULL, the length required is returned in olen.
 *
 * @param [in]      ssl   SSL/TLS object.
 * @param [out]     out   Buffer to hold keying material. May be NULL.
 * @param [in, out] olen  In: size of buffer. Out: length of keying material.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl or olen is NULL.
 * @return  EXT_MISSING when DTLS-SRTP is not in use.
 * @return  LENGTH_ONLY_E when out is NULL and olen has been set.
 * @return  BUFFER_E when the buffer is too small.
 */
int wolfSSL_export_dtls_srtp_keying_material(WOLFSSL* ssl,
    unsigned char* out, size_t* olen)
{
    const WOLFSSL_SRTP_PROTECTION_PROFILE* profile = NULL;

    if (ssl == NULL || olen == NULL) {
        return BAD_FUNC_ARG;
    }

    profile = DtlsSrtpFindProfile(NULL, 0, ssl->dtlsSrtpId);
    if (profile == NULL) {
        WOLFSSL_MSG("Not using DTLS SRTP");
        return EXT_MISSING;
    }
    if (out == NULL) {
        *olen = (size_t)profile->kdfBits;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    if (*olen < (size_t)profile->kdfBits) {
        return BUFFER_E;
    }

    return wolfSSL_export_keying_material(ssl, out, (size_t)profile->kdfBits,
            DTLS_SRTP_KEYING_MATERIAL_LABEL,
            XSTR_SIZEOF(DTLS_SRTP_KEYING_MATERIAL_LABEL), NULL, 0, 0);
}

#endif /* WOLFSSL_SRTP */


#ifdef WOLFSSL_DTLS_DROP_STATS

/* Get the DTLS dropped-record statistics for the object.
 *
 * @param [in]  ssl              SSL/TLS object.
 * @param [out] macDropCount     Number of records dropped on MAC failure.
 * @param [out] replayDropCount  Number of records dropped as replays.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_dtls_get_drop_stats(WOLFSSL* ssl,
                                word32* macDropCount, word32* replayDropCount)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_dtls_get_drop_stats");

    if (ssl == NULL)
        ret = BAD_FUNC_ARG;
    else {
        ret = WOLFSSL_SUCCESS;
        if (macDropCount != NULL)
            *macDropCount = ssl->macDropCount;
        if (replayDropCount != NULL)
            *replayDropCount = ssl->replayDropCount;
    }

    WOLFSSL_LEAVE("wolfSSL_dtls_get_drop_stats", ret);
    return ret;
}

#endif /* WOLFSSL_DTLS_DROP_STATS */


#if defined(WOLFSSL_MULTICAST)

/* Set the multicast member id on the context and enable multicast.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] id   Multicast member id.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL or id is out of range.
 */
int wolfSSL_CTX_mcast_set_member_id(WOLFSSL_CTX* ctx, word16 id)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_CTX_mcast_set_member_id");

    if (ctx == NULL || id > WOLFSSL_MAX_8BIT)
        ret = BAD_FUNC_ARG;

    if (ret == 0) {
        ctx->haveEMS = 0;
        ctx->haveMcast = 1;
        ctx->mcastID = (byte)id;
#ifndef WOLFSSL_USER_IO
        ctx->CBIORecv = EmbedReceiveFromMcast;
#endif /* WOLFSSL_USER_IO */

        ret = WOLFSSL_SUCCESS;
    }
    WOLFSSL_LEAVE("wolfSSL_CTX_mcast_set_member_id", ret);
    return ret;
}

/* Get the maximum number of multicast peers supported.
 *
 * @return  Maximum number of multicast peers.
 */
int wolfSSL_mcast_get_max_peers(void)
{
    return WOLFSSL_MULTICAST_PEERS;
}

#ifdef WOLFSSL_DTLS
/* Determine the next highwater mark from the current sequence number.
 *
 * @param [in] cur     Current sequence number.
 * @param [in] first   First highwater threshold.
 * @param [in] second  Second highwater threshold.
 * @param [in] high    Maximum highwater threshold.
 * @return  Next highwater mark, or 0 when cur is at or above high.
 */
static WC_INLINE word32 UpdateHighwaterMark(word32 cur, word32 first,
                                         word32 second, word32 high)
{
    word32 newCur = 0;

    if (cur < first)
        newCur = first;
    else if (cur < second)
        newCur = second;
    else if (cur < high)
        newCur = high;

    return newCur;
}
#endif /* WOLFSSL_DTLS */


/* Set the master secret and derived keys directly on the object.
 *
 * Used with multicast to install externally derived keys.
 *
 * @param [in] ssl              SSL/TLS object.
 * @param [in] epoch            DTLS epoch to use.
 * @param [in] preMasterSecret  Pre-master secret data.
 * @param [in] preMasterSz      Length of pre-master secret in bytes.
 * @param [in] clientRandom     Client random data (RAN_LEN bytes).
 * @param [in] serverRandom     Server random data (RAN_LEN bytes).
 * @param [in] suite            Cipher suite bytes (2).
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FATAL_ERROR on error, including invalid arguments.
 */
int wolfSSL_set_secret(WOLFSSL* ssl, word16 epoch,
                       const byte* preMasterSecret, word32 preMasterSz,
                       const byte* clientRandom, const byte* serverRandom,
                       const byte* suite)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_set_secret");

    if (ssl == NULL || preMasterSecret == NULL ||
        preMasterSz == 0 || preMasterSz > ENCRYPT_LEN ||
        clientRandom == NULL || serverRandom == NULL || suite == NULL) {

        ret = BAD_FUNC_ARG;
    }

    if (ret == 0 && ssl->arrays->preMasterSecret == NULL) {
        ssl->arrays->preMasterSz = ENCRYPT_LEN;
        ssl->arrays->preMasterSecret = (byte*)XMALLOC(ENCRYPT_LEN, ssl->heap,
            DYNAMIC_TYPE_SECRET);
        if (ssl->arrays->preMasterSecret == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        XMEMCPY(ssl->arrays->preMasterSecret, preMasterSecret, preMasterSz);
        XMEMSET(ssl->arrays->preMasterSecret + preMasterSz, 0,
            ENCRYPT_LEN - preMasterSz);
        ssl->arrays->preMasterSz = preMasterSz;
        XMEMCPY(ssl->arrays->clientRandom, clientRandom, RAN_LEN);
        XMEMCPY(ssl->arrays->serverRandom, serverRandom, RAN_LEN);
        ssl->options.cipherSuite0 = suite[0];
        ssl->options.cipherSuite = suite[1];

        ret = SetCipherSpecs(ssl);
    }

    if (ret == 0)
        ret = MakeTlsMasterSecret(ssl);

    if (ret == 0) {
        ssl->keys.encryptionOn = 1;
        ret = SetKeysSide(ssl, ENCRYPT_AND_DECRYPT_SIDE);
    }

    if (ret == 0) {
        if (ssl->options.dtls) {
        #ifdef WOLFSSL_DTLS
            WOLFSSL_DTLS_PEERSEQ* peerSeq;
            int i;

            ssl->keys.dtls_epoch = epoch;
            for (i = 0, peerSeq = ssl->keys.peerSeq;
                 i < WOLFSSL_DTLS_PEERSEQ_SZ;
                 i++, peerSeq++) {

                peerSeq->nextEpoch = epoch;
                peerSeq->prevSeq_lo = peerSeq->nextSeq_lo;
                peerSeq->prevSeq_hi = peerSeq->nextSeq_hi;
                peerSeq->nextSeq_lo = 0;
                peerSeq->nextSeq_hi = 0;
                XMEMCPY(peerSeq->prevWindow, peerSeq->window, DTLS_SEQ_SZ);
                XMEMSET(peerSeq->window, 0, DTLS_SEQ_SZ);
                peerSeq->highwaterMark = UpdateHighwaterMark(0,
                        ssl->ctx->mcastFirstSeq,
                        ssl->ctx->mcastSecondSeq,
                        ssl->ctx->mcastMaxSeq);
            }
        #else
            (void)epoch;
        #endif
        }
        FreeHandshakeResources(ssl);
        ret = WOLFSSL_SUCCESS;
    }
    else {
        if (ssl)
            ssl->error = ret;
        ret = WOLFSSL_FATAL_ERROR;
    }
    WOLFSSL_LEAVE("wolfSSL_set_secret", ret);
    return ret;
}


#ifdef WOLFSSL_DTLS

/* Add or remove a peer from the multicast peer list.
 *
 * @param [in] ssl     SSL/TLS object.
 * @param [in] peerId  Peer id to add or remove.
 * @param [in] sub     0 to add the peer, non-zero to remove it.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL or peerId is out of range.
 * @return  WOLFSSL_FATAL_ERROR when the peer list is full.
 */
int wolfSSL_mcast_peer_add(WOLFSSL* ssl, word16 peerId, int sub)
{
    WOLFSSL_DTLS_PEERSEQ* p = NULL;
    int ret = WOLFSSL_SUCCESS;
    int i;

    WOLFSSL_ENTER("wolfSSL_mcast_peer_add");
    if (ssl == NULL || peerId > WOLFSSL_MAX_8BIT)
        return BAD_FUNC_ARG;

    if (!sub) {
        /* Make sure it isn't already present, while keeping the first
         * open spot. */
        for (i = 0; i < WOLFSSL_DTLS_PEERSEQ_SZ; i++) {
            if (ssl->keys.peerSeq[i].peerId == INVALID_PEER_ID)
                p = &ssl->keys.peerSeq[i];
            if (ssl->keys.peerSeq[i].peerId == peerId) {
                WOLFSSL_MSG("Peer ID already in multicast peer list.");
                p = NULL;
            }
        }

        if (p != NULL) {
            XMEMSET(p, 0, sizeof(WOLFSSL_DTLS_PEERSEQ));
            p->peerId = peerId;
            p->highwaterMark = UpdateHighwaterMark(0,
                ssl->ctx->mcastFirstSeq,
                ssl->ctx->mcastSecondSeq,
                ssl->ctx->mcastMaxSeq);
        }
        else {
            WOLFSSL_MSG("No room in peer list.");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    else {
        for (i = 0; i < WOLFSSL_DTLS_PEERSEQ_SZ; i++) {
            if (ssl->keys.peerSeq[i].peerId == peerId)
                p = &ssl->keys.peerSeq[i];
        }

        if (p != NULL) {
            p->peerId = INVALID_PEER_ID;
        }
        else {
            WOLFSSL_MSG("Peer not found in list.");
        }
    }

    WOLFSSL_LEAVE("wolfSSL_mcast_peer_add", ret);
    return ret;
}


/* Determine whether a multicast peer is known and active.
 *
 * @param [in] ssl     SSL/TLS object.
 * @param [in] peerId  Peer id to look up.
 * @return  1 when the peer is in the list with a non-zero sequence number.
 * @return  0 when the peer is not known or has not sent data.
 * @return  BAD_FUNC_ARG when ssl is NULL or peerId is out of range.
 */
int wolfSSL_mcast_peer_known(WOLFSSL* ssl, unsigned short peerId)
{
    int known = 0;
    int i;

    WOLFSSL_ENTER("wolfSSL_mcast_peer_known");

    if (ssl == NULL || peerId > WOLFSSL_MAX_8BIT) {
        return BAD_FUNC_ARG;
    }

    for (i = 0; i < WOLFSSL_DTLS_PEERSEQ_SZ; i++) {
        if (ssl->keys.peerSeq[i].peerId == peerId) {
            if (ssl->keys.peerSeq[i].nextSeq_hi ||
                ssl->keys.peerSeq[i].nextSeq_lo) {

                known = 1;
            }
            break;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_mcast_peer_known", known);
    return known;
}


/* Set the multicast highwater callback and thresholds on the context.
 *
 * @param [in] ctx     SSL/TLS context object.
 * @param [in] maxSeq  Maximum sequence number threshold.
 * @param [in] first   First sequence number threshold.
 * @param [in] second  Second sequence number threshold.
 * @param [in] cb      Highwater callback.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when an argument is NULL or thresholds are invalid.
 */
int wolfSSL_CTX_mcast_set_highwater_cb(WOLFSSL_CTX* ctx, word32 maxSeq,
                                       word32 first, word32 second,
                                       CallbackMcastHighwater cb)
{
    if (ctx == NULL || (second && first > second) ||
        first > maxSeq || second > maxSeq || cb == NULL) {

        return BAD_FUNC_ARG;
    }

    ctx->mcastHwCb = cb;
    ctx->mcastFirstSeq = first;
    ctx->mcastSecondSeq = second;
    ctx->mcastMaxSeq = maxSeq;

    return WOLFSSL_SUCCESS;
}


/* Set the user context passed to the multicast highwater callback.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] ctx  User context for the highwater callback.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl or ctx is NULL.
 */
int wolfSSL_mcast_set_highwater_ctx(WOLFSSL* ssl, void* ctx)
{
    if (ssl == NULL || ctx == NULL)
        return BAD_FUNC_ARG;

    ssl->mcastHwCbCtx = ctx;

    return WOLFSSL_SUCCESS;
}

#endif /* WOLFSSL_DTLS */

#endif /* WOLFSSL_MULTICAST */


#endif /* WOLFSSL_LEANPSK */


#ifndef NO_TLS
#ifdef WOLFSSL_MULTICAST

/* Read application data from a multicast DTLS object.
 *
 * @param [in]  ssl   SSL/TLS object.
 * @param [out] id    Peer id the data was received from. May be NULL.
 * @param [out] data  Buffer to hold the data read.
 * @param [in]  sz    Size of the buffer in bytes.
 * @return  Number of bytes read on success.
 * @return  BAD_FUNC_ARG when ssl is NULL or sz is negative.
 * @return  Negative value on error.
 */
int wolfSSL_mcast_read(WOLFSSL* ssl, word16* id, void* data, int sz)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_mcast_read");

    if ((ssl == NULL) || (sz < 0))
        return BAD_FUNC_ARG;

    ret = wolfSSL_read_internal(ssl, data, (size_t)sz, FALSE);
    if (ssl->options.dtls && ssl->options.haveMcast && id != NULL)
        *id = ssl->keys.curPeerId;
    return ret;
}

#endif /* WOLFSSL_MULTICAST */
#endif /* !NO_TLS */


#ifdef WOLFSSL_DTLS
/* Get the DTLS MAC secret for the requested side and epoch.
 *
 * @param [in] ssl         SSL/TLS object.
 * @param [in] verify      1 for the verify (read) secret, 0 for the write one.
 * @param [in] epochOrder  Epoch order: PEER_ORDER, PREV_ORDER or CUR_ORDER.
 * @return  MAC secret on success.
 * @return  NULL when ssl is NULL, AEAD-only build, or epoch order is unknown.
 */
const byte* wolfSSL_GetDtlsMacSecret(WOLFSSL* ssl, int verify, int epochOrder)
{
#ifndef WOLFSSL_AEAD_ONLY
    Keys* keys = NULL;

    (void)epochOrder;

    if (ssl == NULL)
        return NULL;

#ifdef HAVE_SECURE_RENEGOTIATION
    switch (epochOrder) {
    case PEER_ORDER:
        if (IsDtlsMsgSCRKeys(ssl))
            keys = &ssl->secure_renegotiation->tmp_keys;
        else
            keys = &ssl->keys;
        break;
    case PREV_ORDER:
        keys = &ssl->keys;
        break;
    case CUR_ORDER:
        if (DtlsUseSCRKeys(ssl))
            keys = &ssl->secure_renegotiation->tmp_keys;
        else
            keys = &ssl->keys;
        break;
    default:
        WOLFSSL_MSG("Unknown epoch order");
        return NULL;
    }
#else
    keys = &ssl->keys;
#endif

    if ( (ssl->options.side == WOLFSSL_CLIENT_END && !verify) ||
         (ssl->options.side == WOLFSSL_SERVER_END &&  verify) )
        return keys->client_write_MAC_secret;
    else
        return keys->server_write_MAC_secret;
#else
    (void)ssl;
    (void)verify;
    (void)epochOrder;

    return NULL;
#endif
}
#endif /* WOLFSSL_DTLS */


/* Get whether the DTLS object is using non-blocking I/O.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when non-blocking I/O is enabled.
 * @return  0 when disabled or not a DTLS object.
 * @return  WOLFSSL_FAILURE when ssl is NULL.
 */
int wolfSSL_dtls_get_using_nonblock(WOLFSSL* ssl)
{
    int useNb = 0;

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

    WOLFSSL_ENTER("wolfSSL_dtls_get_using_nonblock");
    if (ssl->options.dtls) {
#ifdef WOLFSSL_DTLS
        useNb = ssl->options.dtlsUseNonblock;
#endif
    }
    else {
        WOLFSSL_MSG("wolfSSL_dtls_get_using_nonblock() is "
                    "DEPRECATED for non-DTLS use.");
    }
    return useNb;
}


#ifndef WOLFSSL_LEANPSK

/* Set whether the DTLS object uses non-blocking I/O.
 *
 * @param [in] ssl       SSL/TLS object.
 * @param [in] nonblock  1 to use non-blocking I/O, 0 otherwise.
 */
void wolfSSL_dtls_set_using_nonblock(WOLFSSL* ssl, int nonblock)
{
    (void)nonblock;

    WOLFSSL_ENTER("wolfSSL_dtls_set_using_nonblock");

    if (ssl == NULL)
        return;

    if (ssl->options.dtls) {
#ifdef WOLFSSL_DTLS
        ssl->options.dtlsUseNonblock = (nonblock != 0);
#endif
    }
    else {
        WOLFSSL_MSG("wolfSSL_dtls_set_using_nonblock() is "
                    "DEPRECATED for non-DTLS use.");
    }
}


#ifdef WOLFSSL_DTLS

/* Get the current DTLS receive timeout, in seconds.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Current timeout in seconds, or 0 when ssl is NULL.
 */
int wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl)
{
    int timeout = 0;
    if (ssl)
        timeout = ssl->dtls_timeout;

    WOLFSSL_LEAVE("wolfSSL_dtls_get_current_timeout", timeout);
    return timeout;
}

#ifdef WOLFSSL_DTLS13

/* Determine whether a short receive timeout should be used.
 *
 * Recommended to be at most 1/4 of wolfSSL_dtls_get_current_timeout().
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when a short timeout should be used.
 * @return  0 otherwise, or when ssl is NULL.
 */
int wolfSSL_dtls13_use_quick_timeout(WOLFSSL* ssl)
{
    return ssl != NULL && ssl->dtls13FastTimeout;
}

/* Set whether a DTLS 1.3 connection sends acks immediately on a disruption.
 *
 * Sending more acks may increase traffic but can speed up the handshake.
 *
 * @param [in] ssl    SSL/TLS object.
 * @param [in] value  Non-zero to send more acks, 0 otherwise.
 */
void wolfSSL_dtls13_set_send_more_acks(WOLFSSL* ssl, int value)
{
    if (ssl != NULL)
        ssl->options.dtls13SendMoreAcks = !!value;
}
#endif /* WOLFSSL_DTLS13 */

/* Get the time left until the next DTLS timeout.
 *
 * @param [in]  ssl       SSL/TLS object.
 * @param [out] timeleft  Time left until the next timeout.
 * @return  0 always.
 */
int wolfSSL_DTLSv1_get_timeout(WOLFSSL* ssl, WOLFSSL_TIMEVAL* timeleft)
{
    if (ssl && timeleft) {
        XMEMSET(timeleft, 0, sizeof(WOLFSSL_TIMEVAL));
        timeleft->tv_sec = ssl->dtls_timeout;
    }
    return 0;
}

#ifndef NO_WOLFSSL_STUB
/* Handle a DTLS timeout.
 *
 * Not implemented - stub for OpenSSL compatibility.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  0 always.
 */
int wolfSSL_DTLSv1_handle_timeout(WOLFSSL* ssl)
{
    WOLFSSL_STUB("SSL_DTLSv1_handle_timeout");
    (void)ssl;
    return 0;
}
#endif

#ifndef NO_WOLFSSL_STUB
/* Set the initial DTLS timeout duration.
 *
 * Not implemented - stub for OpenSSL compatibility.
 *
 * @param [in] ssl          SSL/TLS object.
 * @param [in] duration_ms  Initial timeout duration in milliseconds.
 */
void wolfSSL_DTLSv1_set_initial_timeout_duration(WOLFSSL* ssl,
    word32 duration_ms)
{
    WOLFSSL_STUB("SSL_DTLSv1_set_initial_timeout_duration");
    (void)ssl;
    (void)duration_ms;
}
#endif

/* Set the initial DTLS receive timeout, in seconds, on the object.
 *
 * @param [in] ssl      SSL/TLS object.
 * @param [in] timeout  Initial timeout in seconds.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL, timeout is negative or greater than
 *          the maximum timeout.
 */
int wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int timeout)
{
    if (ssl == NULL || timeout < 0)
        return BAD_FUNC_ARG;

    if (timeout > ssl->dtls_timeout_max) {
        WOLFSSL_MSG("Can't set dtls timeout init greater than dtls timeout "
                    "max");
        return BAD_FUNC_ARG;
    }

    ssl->dtls_timeout_init = timeout;
    ssl->dtls_timeout = timeout;

    return WOLFSSL_SUCCESS;
}


/* Set the maximum DTLS receive timeout, in seconds, on the object.
 *
 * @param [in] ssl      SSL/TLS object.
 * @param [in] timeout  Maximum timeout in seconds.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL, timeout is negative or less than
 *          the initial timeout.
 */
int wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int timeout)
{
    if (ssl == NULL || timeout < 0)
        return BAD_FUNC_ARG;

    if (timeout < ssl->dtls_timeout_init) {
        WOLFSSL_MSG("Can't set dtls timeout max less than dtls timeout init");
        return BAD_FUNC_ARG;
    }

    ssl->dtls_timeout_max = timeout;

    return WOLFSSL_SUCCESS;
}


/* Process a DTLS timeout, retransmitting messages as needed.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FATAL_ERROR when ssl is NULL, not DTLS, or on error.
 */
int wolfSSL_dtls_got_timeout(WOLFSSL* ssl)
{
    int result = WOLFSSL_SUCCESS;
    WOLFSSL_ENTER("wolfSSL_dtls_got_timeout");

    if (ssl == NULL || !ssl->options.dtls)
        return WOLFSSL_FATAL_ERROR;

#ifdef WOLFSSL_DTLS13
    if (IsAtLeastTLSv1_3(ssl->version)) {
        result = Dtls13RtxTimeout(ssl);
        if (result < 0) {
            if (result == WC_NO_ERR_TRACE(WANT_WRITE))
                ssl->dtls13SendingAckOrRtx = 1;
            ssl->error = result;
            WOLFSSL_ERROR(result);
            return WOLFSSL_FATAL_ERROR;
        }

        return WOLFSSL_SUCCESS;
    }
#endif /* WOLFSSL_DTLS13 */

    /* Do we have any 1.2 messages stored? */
    if (ssl->dtls_tx_msg_list != NULL || ssl->dtls_tx_msg != NULL) {
        if (DtlsMsgPoolTimeout(ssl) < 0){
            ssl->error = SOCKET_ERROR_E;
            WOLFSSL_ERROR(ssl->error);
            result = WOLFSSL_FATAL_ERROR;
        }
        else if ((result = DtlsMsgPoolSend(ssl, 0)) < 0)  {
            ssl->error = result;
            WOLFSSL_ERROR(result);
            result = WOLFSSL_FATAL_ERROR;
        }
        else {
            /* Reset return value to success */
            result = WOLFSSL_SUCCESS;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_dtls_got_timeout", result);
    return result;
}


/* Retransmit all stored DTLS handshake messages.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FATAL_ERROR when ssl is NULL or on error.
 */
int wolfSSL_dtls_retransmit(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_dtls_retransmit");

    if (ssl == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (!ssl->options.handShakeDone) {
        int result;
#ifdef WOLFSSL_DTLS13
        if (IsAtLeastTLSv1_3(ssl->version))
            result = Dtls13DoScheduledWork(ssl);
        else
#endif
            result = DtlsMsgPoolSend(ssl, 0);
        if (result < 0) {
            ssl->error = result;
            WOLFSSL_ERROR(result);
            return WOLFSSL_FATAL_ERROR;
        }
    }

    return WOLFSSL_SUCCESS;
}

#endif /* DTLS */
#endif /* LEANPSK */


#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)

/* Set the DTLS cookie secret used to generate HelloVerifyRequest cookies.
 *
 * When secret is NULL a new secret is randomly generated. The object's RNG
 * must be initialized. This is not an SSL function.
 *
 * @param [in] ssl       SSL/TLS object.
 * @param [in] secret    Cookie secret data, or NULL to generate one.
 * @param [in] secretSz  Length of secret in bytes, 0 to use the default.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ssl is NULL or secret is set with size 0.
 * @return  MEMORY_ERROR on allocation failure.
 */
int wolfSSL_DTLS_SetCookieSecret(WOLFSSL* ssl,
                                 const byte* secret, word32 secretSz)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_DTLS_SetCookieSecret");

    if (ssl == NULL) {
        WOLFSSL_MSG("need a SSL object");
        return BAD_FUNC_ARG;
    }

    if (secret != NULL && secretSz == 0) {
        WOLFSSL_MSG("can't have a new secret without a size");
        return BAD_FUNC_ARG;
    }

    /* If secretSz is 0, use the default size. */
    if (secretSz == 0)
        secretSz = COOKIE_SECRET_SZ;

    if (secretSz != ssl->buffers.dtlsCookieSecret.length) {
        byte* newSecret;

        if (ssl->buffers.dtlsCookieSecret.buffer != NULL) {
            ForceZero(ssl->buffers.dtlsCookieSecret.buffer,
                      ssl->buffers.dtlsCookieSecret.length);
            XFREE(ssl->buffers.dtlsCookieSecret.buffer,
                  ssl->heap, DYNAMIC_TYPE_COOKIE_PWD);
        }

        newSecret = (byte*)XMALLOC(secretSz, ssl->heap,DYNAMIC_TYPE_COOKIE_PWD);
        if (newSecret == NULL) {
            ssl->buffers.dtlsCookieSecret.buffer = NULL;
            ssl->buffers.dtlsCookieSecret.length = 0;
            WOLFSSL_MSG("couldn't allocate new cookie secret");
            return MEMORY_ERROR;
        }
        ssl->buffers.dtlsCookieSecret.buffer = newSecret;
        ssl->buffers.dtlsCookieSecret.length = secretSz;
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("wolfSSL_DTLS_SetCookieSecret secret",
            ssl->buffers.dtlsCookieSecret.buffer,
            ssl->buffers.dtlsCookieSecret.length);
    #endif
    }

    /* If the supplied secret is NULL, randomly generate a new secret. */
    if (secret == NULL) {
        ret = wc_RNG_GenerateBlock(ssl->rng,
                             ssl->buffers.dtlsCookieSecret.buffer, secretSz);
    }
    else
        XMEMCPY(ssl->buffers.dtlsCookieSecret.buffer, secret, secretSz);

    WOLFSSL_LEAVE("wolfSSL_DTLS_SetCookieSecret", 0);
    return ret;
}

#endif /* WOLFSSL_DTLS && !NO_WOLFSSL_SERVER */

#endif /* !WOLFCRYPT_ONLY */

#endif /* !WOLFSSL_SSL_API_DTLS_INCLUDED */
