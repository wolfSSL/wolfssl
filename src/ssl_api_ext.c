/* ssl_api_ext.c
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

#if !defined(WOLFSSL_SSL_API_EXT_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning ssl_api_ext.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef WOLFCRYPT_ONLY
#ifndef NO_TLS

#ifdef HAVE_SNI

/* Set the Server Name Indication extension data on the object.
 *
 * @param [in] ssl   SSL/TLS object.
 * @param [in] type  SNI type, e.g. WOLFSSL_SNI_HOST_NAME.
 * @param [in] data  SNI data.
 * @param [in] size  Length of SNI data in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  Negative value on error.
 */
WOLFSSL_ABI
int wolfSSL_UseSNI(WOLFSSL* ssl, byte type, const void* data, word16 size)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ssl->extensions, type, data, size, ssl->heap);
}


/* Set the Server Name Indication extension data on the context.
 *
 * @param [in] ctx   SSL/TLS context object.
 * @param [in] type  SNI type, e.g. WOLFSSL_SNI_HOST_NAME.
 * @param [in] data  SNI data.
 * @param [in] size  Length of SNI data in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 * @return  Negative value on error.
 */
WOLFSSL_ABI
int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, byte type, const void* data,
                                                                    word16 size)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ctx->extensions, type, data, size, ctx->heap);
}

#ifndef NO_WOLFSSL_SERVER

/* Set options for the Server Name Indication extension on the object.
 *
 * @param [in] ssl      SSL/TLS object.
 * @param [in] type     SNI type.
 * @param [in] options  Bitmask of SNI options.
 */
void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, byte type, byte options)
{
    if ((ssl != NULL) && (ssl->extensions != NULL)) {
        TLSX_SNI_SetOptions(ssl->extensions, type, options);
    }
}


/* Set options for the Server Name Indication extension on the context.
 *
 * @param [in] ctx      SSL/TLS context object.
 * @param [in] type     SNI type.
 * @param [in] options  Bitmask of SNI options.
 */
void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx, byte type, byte options)
{
    if ((ctx != NULL) && (ctx->extensions != NULL)) {
        TLSX_SNI_SetOptions(ctx->extensions, type, options);
    }
}


/* Get the status of the Server Name Indication extension on the object.
 *
 * @param [in] ssl   SSL/TLS object.
 * @param [in] type  SNI type.
 * @return  SNI status for the type.
 */
byte wolfSSL_SNI_Status(WOLFSSL* ssl, byte type)
{
    return TLSX_SNI_Status((ssl != NULL) ? ssl->extensions : NULL, type);
}


/* Get the Server Name Indication request data received from the peer.
 *
 * @param [in]  ssl   SSL/TLS object.
 * @param [in]  type  SNI type.
 * @param [out] data  Pointer to the SNI request data. May be NULL.
 * @return  Length of the SNI request data in bytes, or 0 when none.
 */
word16 wolfSSL_SNI_GetRequest(WOLFSSL* ssl, byte type, void** data)
{
    if (data)
        *data = NULL;

    if (ssl && ssl->extensions)
        return TLSX_SNI_GetRequest(ssl->extensions, type, data, 0);

    return 0;
}


/* Get the Server Name Indication data from a raw ClientHello buffer.
 *
 * @param [in]      clientHello  ClientHello message buffer.
 * @param [in]      helloSz      Length of the ClientHello in bytes.
 * @param [in]      type         SNI type.
 * @param [out]     sni          Buffer to hold the SNI data.
 * @param [in, out] inOutSz      In: size of buffer. Out: length of SNI data.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when an argument is NULL or a size is zero.
 */
int wolfSSL_SNI_GetFromBuffer(const byte* clientHello, word32 helloSz,
                              byte type, byte* sni, word32* inOutSz)
{
    if (clientHello && helloSz > 0 && sni && inOutSz && *inOutSz > 0)
        return TLSX_SNI_GetFromBuffer(clientHello, helloSz, type, sni, inOutSz);

    return BAD_FUNC_ARG;
}

#endif /* !NO_WOLFSSL_SERVER */

#endif /* HAVE_SNI */


#ifdef HAVE_TRUSTED_CA

/* Set the Trusted CA Indication extension on the object.
 *
 * @param [in] ssl       SSL/TLS object.
 * @param [in] type      Trusted CA identifier type.
 * @param [in] certId    Certificate identifier data.
 * @param [in] certIdSz  Length of certificate identifier in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL or arguments are inconsistent with
 *          the type.
 */
int wolfSSL_UseTrustedCA(WOLFSSL* ssl, byte type,
    const byte* certId, word32 certIdSz)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (type == WOLFSSL_TRUSTED_CA_PRE_AGREED) {
        if (certId != NULL || certIdSz != 0)
            return BAD_FUNC_ARG;
    }
    else if (type == WOLFSSL_TRUSTED_CA_X509_NAME) {
        if (certId == NULL || certIdSz == 0)
            return BAD_FUNC_ARG;
    }
    #ifndef NO_SHA
    else if (type == WOLFSSL_TRUSTED_CA_KEY_SHA1 ||
            type == WOLFSSL_TRUSTED_CA_CERT_SHA1) {
        if (certId == NULL || certIdSz != WC_SHA_DIGEST_SIZE)
            return BAD_FUNC_ARG;
    }
    #endif
    else
        return BAD_FUNC_ARG;

    return TLSX_UseTrustedCA(&ssl->extensions,
            type, certId, certIdSz, ssl->heap);
}

#endif /* HAVE_TRUSTED_CA */


#ifdef HAVE_MAX_FRAGMENT
#ifndef NO_WOLFSSL_CLIENT

/* Set the Maximum Fragment Length extension on the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] mfl  Maximum fragment length code, e.g. WOLFSSL_MFL_2_9.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  Negative value on error.
 */
int wolfSSL_UseMaxFragment(WOLFSSL* ssl, byte mfl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_ALLOW_MAX_FRAGMENT_ADJUST
    /* The following is a non-standard way to reconfigure the max packet size
        post-handshake for wolfSSL_write/wolfSSL_read */
    if (ssl->options.handShakeState == HANDSHAKE_DONE) {
        switch (mfl) {
            case WOLFSSL_MFL_2_8 : ssl->max_fragment =  256; break;
            case WOLFSSL_MFL_2_9 : ssl->max_fragment =  512; break;
            case WOLFSSL_MFL_2_10: ssl->max_fragment = 1024; break;
            case WOLFSSL_MFL_2_11: ssl->max_fragment = 2048; break;
            case WOLFSSL_MFL_2_12: ssl->max_fragment = 4096; break;
            case WOLFSSL_MFL_2_13: ssl->max_fragment = 8192; break;
            default: ssl->max_fragment = MAX_RECORD_SIZE; break;
        }
        return WOLFSSL_SUCCESS;
    }
#endif /* WOLFSSL_MAX_FRAGMENT_ADJUST */

    /* This call sets the max fragment TLS extension, which gets sent to server.
        The server_hello response is what sets the `ssl->max_fragment` in
        TLSX_MFL_Parse */
    return TLSX_UseMaxFragment(&ssl->extensions, mfl, ssl->heap);
}


/* Set the Maximum Fragment Length extension on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] mfl  Maximum fragment length code, e.g. WOLFSSL_MFL_2_9.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 * @return  Negative value on error.
 */
int wolfSSL_CTX_UseMaxFragment(WOLFSSL_CTX* ctx, byte mfl)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseMaxFragment(&ctx->extensions, mfl, ctx->heap);
}

#endif /* NO_WOLFSSL_CLIENT */
#endif /* HAVE_MAX_FRAGMENT */

#ifdef HAVE_TRUNCATED_HMAC
#ifndef NO_WOLFSSL_CLIENT

/* Set the Truncated HMAC extension on the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  Negative value on error.
 */
int wolfSSL_UseTruncatedHMAC(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseTruncatedHMAC(&ssl->extensions, ssl->heap);
}


/* Set the Truncated HMAC extension on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 * @return  Negative value on error.
 */
int wolfSSL_CTX_UseTruncatedHMAC(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseTruncatedHMAC(&ctx->extensions, ctx->heap);
}

#endif /* NO_WOLFSSL_CLIENT */
#endif /* HAVE_TRUNCATED_HMAC */

/* Elliptic Curves */
#if defined(HAVE_SUPPORTED_CURVES)

/* Determine whether a named group is a supported curve or FFDHE group.
 *
 * @param [in] name  Named group identifier.
 * @return  1 when the named group is valid.
 * @return  0 otherwise.
 */
static int isValidCurveGroup(word16 name)
{
    switch (name) {
        case WOLFSSL_ECC_SECP160K1:
        case WOLFSSL_ECC_SECP160R1:
        case WOLFSSL_ECC_SECP160R2:
        case WOLFSSL_ECC_SECP192K1:
        case WOLFSSL_ECC_SECP192R1:
        case WOLFSSL_ECC_SECP224K1:
        case WOLFSSL_ECC_SECP224R1:
        case WOLFSSL_ECC_SECP256K1:
        case WOLFSSL_ECC_SECP256R1:
        case WOLFSSL_ECC_SECP384R1:
        case WOLFSSL_ECC_SECP521R1:
        case WOLFSSL_ECC_BRAINPOOLP256R1:
        case WOLFSSL_ECC_BRAINPOOLP384R1:
        case WOLFSSL_ECC_BRAINPOOLP512R1:
        case WOLFSSL_ECC_SM2P256V1:
        case WOLFSSL_ECC_X25519:
        case WOLFSSL_ECC_X448:
        case WOLFSSL_ECC_BRAINPOOLP256R1TLS13:
        case WOLFSSL_ECC_BRAINPOOLP384R1TLS13:
        case WOLFSSL_ECC_BRAINPOOLP512R1TLS13:

        case WOLFSSL_FFDHE_2048:
        case WOLFSSL_FFDHE_3072:
        case WOLFSSL_FFDHE_4096:
        case WOLFSSL_FFDHE_6144:
        case WOLFSSL_FFDHE_8192:

#ifdef WOLFSSL_HAVE_MLKEM
#ifndef WOLFSSL_NO_ML_KEM
    #ifndef WOLFSSL_TLS_NO_MLKEM_STANDALONE
        case WOLFSSL_ML_KEM_512:
        case WOLFSSL_ML_KEM_768:
        case WOLFSSL_ML_KEM_1024:
    #endif /* !WOLFSSL_TLS_NO_MLKEM_STANDALONE */
    #ifdef WOLFSSL_PQC_HYBRIDS
        case WOLFSSL_SECP384R1MLKEM1024:
        case WOLFSSL_X25519MLKEM768:
        case WOLFSSL_SECP256R1MLKEM768:
    #endif /* WOLFSSL_PQC_HYBRIDS */
    #ifdef WOLFSSL_EXTRA_PQC_HYBRIDS
        case WOLFSSL_SECP256R1MLKEM512:
        case WOLFSSL_SECP384R1MLKEM768:
        case WOLFSSL_SECP521R1MLKEM1024:
        case WOLFSSL_X25519MLKEM512:
        case WOLFSSL_X448MLKEM768:
    #endif /* WOLFSSL_EXTRA_PQC_HYBRIDS */
#endif /* !WOLFSSL_NO_ML_KEM */
#ifdef WOLFSSL_MLKEM_KYBER
        case WOLFSSL_KYBER_LEVEL1:
        case WOLFSSL_KYBER_LEVEL3:
        case WOLFSSL_KYBER_LEVEL5:
        case WOLFSSL_P256_KYBER_LEVEL1:
        case WOLFSSL_P384_KYBER_LEVEL3:
        case WOLFSSL_P521_KYBER_LEVEL5:
        case WOLFSSL_X25519_KYBER_LEVEL1:
        case WOLFSSL_X448_KYBER_LEVEL3:
        case WOLFSSL_X25519_KYBER_LEVEL3:
        case WOLFSSL_P256_KYBER_LEVEL3:
#endif /* WOLFSSL_MLKEM_KYBER */
#endif
            return 1;

        default:
            return 0;
    }
}

/* Set a named group in the Supported Groups extension on the object.
 *
 * @param [in] ssl   SSL/TLS object.
 * @param [in] name  Named group identifier.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL or the group is invalid.
 * @return  WOLFSSL_FAILURE when TLS is not compiled in.
 */
int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name)
{
    if (ssl == NULL || !isValidCurveGroup(name))
        return BAD_FUNC_ARG;

    ssl->options.userCurves = 1;
#if defined(NO_TLS)
    return WOLFSSL_FAILURE;
#else
    return TLSX_UseSupportedCurve(&ssl->extensions, name, ssl->heap,
                                  ssl->options.side);
#endif /* NO_TLS */
}


/* Set a named group in the Supported Groups extension on the context.
 *
 * @param [in] ctx   SSL/TLS context object.
 * @param [in] name  Named group identifier.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL or the group is invalid.
 * @return  WOLFSSL_FAILURE when TLS is not compiled in.
 */
int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx, word16 name)
{
    if (ctx == NULL || !isValidCurveGroup(name))
        return BAD_FUNC_ARG;

    ctx->userCurves = 1;
#if defined(NO_TLS)
    return WOLFSSL_FAILURE;
#else
    return TLSX_UseSupportedCurve(&ctx->extensions, name, ctx->heap,
                                  ctx->method->side);
#endif /* NO_TLS */
}

#if defined(OPENSSL_EXTRA)
/* Validate a list of group identifiers and translate them into named groups.
 *
 * Group values may be wolfSSL named groups or curve NIDs (when ECC is
 * available).
 *
 * @param [in]  groups     Array of group identifiers.
 * @param [in]  count      Number of groups in the array.
 * @param [out] outGroups  Array to hold the named groups. Must have at least
 *                         count entries.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when a group is not recognized.
 */
static int wolfssl_validate_groups(const int* groups, int count, int* outGroups)
{
    int i;
    int ret = WOLFSSL_SUCCESS;

    for (i = 0; i < count; i++) {
        if (isValidCurveGroup((word16)groups[i])) {
            outGroups[i] = groups[i];
        }
#ifdef HAVE_ECC
        else {
            /* Groups may be populated with curve NIDs. */
            int oid = (int)nid2oid(groups[i], oidCurveType);
            int name = (int)GetCurveByOID(oid);
            if (name == 0) {
                WOLFSSL_MSG("Invalid group name");
                ret = WOLFSSL_FAILURE;
                break;
            }
            outGroups[i] = name;
        }
#else
        else {
            WOLFSSL_MSG("Invalid group name");
            ret = WOLFSSL_FAILURE;
            break;
        }
#endif
    }

    return ret;
}

/* Set the list of supported groups on the context.
 *
 * Group values may be wolfSSL named groups or curve NIDs.
 *
 * @param [in] ctx     SSL/TLS context object.
 * @param [in] groups  Array of group identifiers.
 * @param [in] count   Number of groups in the array.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when count is invalid or a group is not recognized.
 */
int wolfSSL_CTX_set1_groups(WOLFSSL_CTX* ctx, int* groups, int count)
{
    int _groups[WOLFSSL_MAX_GROUP_COUNT];
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_CTX_set1_groups");
    if (groups == NULL || count <= 0) {
        WOLFSSL_MSG("Groups NULL or count not positive");
        ret = WOLFSSL_FAILURE;
    }
    else if (count > WOLFSSL_MAX_GROUP_COUNT) {
        WOLFSSL_MSG("Group count exceeds maximum");
        ret = WOLFSSL_FAILURE;
    }
    else {
        /* Translate the input list into named groups, then apply it. */
        ret = wolfssl_validate_groups(groups, count, _groups);
        if (ret == WOLFSSL_SUCCESS) {
            ret = wolfSSL_CTX_set_groups(ctx, _groups, count);
            /* Normalize any non-success result to WOLFSSL_FAILURE. */
            if (ret != WOLFSSL_SUCCESS) {
                ret = WOLFSSL_FAILURE;
            }
        }
    }

    return ret;
}

/* Set the list of supported groups on the object.
 *
 * Group values may be wolfSSL named groups or curve NIDs.
 *
 * @param [in] ssl     SSL/TLS object.
 * @param [in] groups  Array of group identifiers.
 * @param [in] count   Number of groups in the array.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when count is invalid or a group is not recognized.
 */
int wolfSSL_set1_groups(WOLFSSL* ssl, int* groups, int count)
{
    int _groups[WOLFSSL_MAX_GROUP_COUNT];
    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_set1_groups");
    if (groups == NULL || count <= 0) {
        WOLFSSL_MSG("Groups NULL or count not positive");
        ret = WOLFSSL_FAILURE;
    }
    else if (count > WOLFSSL_MAX_GROUP_COUNT) {
        WOLFSSL_MSG("Group count exceeds maximum");
        ret = WOLFSSL_FAILURE;
    }
    else {
        /* Translate the input list into named groups, then apply it. */
        ret = wolfssl_validate_groups(groups, count, _groups);
        if (ret == WOLFSSL_SUCCESS) {
            ret = wolfSSL_set_groups(ssl, _groups, count);
            /* Normalize any non-success result to WOLFSSL_FAILURE. */
            if (ret != WOLFSSL_SUCCESS) {
                ret = WOLFSSL_FAILURE;
            }
        }
    }

    return ret;
}
#endif /* OPENSSL_EXTRA */
#endif /* HAVE_SUPPORTED_CURVES */

/* Application-Layer Protocol Negotiation */
#ifdef HAVE_ALPN

/* Set the Application-Layer Protocol Negotiation extension on the object.
 *
 * @param [in] ssl                    SSL/TLS object.
 * @param [in] protocol_name_list     Comma-separated list of protocol names.
 * @param [in] protocol_name_listSz   Length of the list in bytes.
 * @param [in] options                Bitmask of ALPN options.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when an argument is NULL, the list is too long or
 *          options are unsupported.
 * @return  MEMORY_ERROR on allocation failure.
 */
WOLFSSL_ABI
int wolfSSL_UseALPN(WOLFSSL* ssl, char *protocol_name_list,
    word32 protocol_name_listSz, byte options)
{
    char*  list = NULL;
    char*  ptr = NULL;
    char** token = NULL;
    word16 len;
    int    idx = 0;
    int    ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfSSL_UseALPN");

    if ((ssl == NULL) || (protocol_name_list == NULL)) {
        return BAD_FUNC_ARG;
    }
    else if (protocol_name_listSz > (WOLFSSL_MAX_ALPN_NUMBER *
             WOLFSSL_MAX_ALPN_PROTO_NAME_LEN + WOLFSSL_MAX_ALPN_NUMBER)) {
        WOLFSSL_MSG("Invalid arguments, protocol name list too long");
        return BAD_FUNC_ARG;
    }
    else if ((!(options & WOLFSSL_ALPN_CONTINUE_ON_MISMATCH)) &&
             (!(options & WOLFSSL_ALPN_FAILED_ON_MISMATCH))) {
        WOLFSSL_MSG("Invalid arguments, options not supported");
        return BAD_FUNC_ARG;
    }

    list = (char *)XMALLOC(protocol_name_listSz + 1, ssl->heap,
                           DYNAMIC_TYPE_ALPN);
    token = (char **)XMALLOC(sizeof(char*) * (WOLFSSL_MAX_ALPN_NUMBER + 1),
                             ssl->heap, DYNAMIC_TYPE_ALPN);
    if ((list == NULL) || (token == NULL)) {
        WOLFSSL_MSG("Memory failure");
        ret = MEMORY_ERROR;
    }

    if (ret == WOLFSSL_SUCCESS) {
        XMEMSET(token, 0, sizeof(char *) * (WOLFSSL_MAX_ALPN_NUMBER+1));

        XSTRNCPY(list, protocol_name_list, protocol_name_listSz);
        list[protocol_name_listSz] = '\0';

        /* Read all protocol names from the list. */
        token[idx] = XSTRTOK(list, ",", &ptr);
        while ((idx < WOLFSSL_MAX_ALPN_NUMBER) && (token[idx] != NULL)) {
            token[++idx] = XSTRTOK(NULL, ",", &ptr);
        }

        /* Add the protocol name list to the TLS extension in reverse order. */
        while ((idx--) > 0) {
            len = (word16)XSTRLEN(token[idx]);

            ret = TLSX_UseALPN(&ssl->extensions, token[idx], len, options,
                ssl->heap);
            if (ret != WOLFSSL_SUCCESS) {
                WOLFSSL_MSG("TLSX_UseALPN failure");
                break;
            }
        }
    }

    XFREE(token, ssl->heap, DYNAMIC_TYPE_ALPN);
    XFREE(list, ssl->heap, DYNAMIC_TYPE_ALPN);

    return ret;
}

/* Get the ALPN protocol negotiated for the object.
 *
 * @param [in]  ssl            SSL/TLS object.
 * @param [out] protocol_name  Negotiated protocol name.
 * @param [out] size           Length of the protocol name in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  Negative value on error.
 */
int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char **protocol_name, word16 *size)
{
    return TLSX_ALPN_GetRequest((ssl != NULL) ? ssl->extensions : NULL,
                                (void **)protocol_name, size);
}

/* Get the ALPN protocol list offered by the peer as a comma-separated string.
 *
 * The returned list must be freed with wolfSSL_ALPN_FreePeerProtocol().
 *
 * @param [in]  ssl     SSL/TLS object.
 * @param [out] list    Newly allocated comma-separated protocol list.
 * @param [out] listSz  Length of the list string.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when an argument is NULL.
 * @return  BUFFER_ERROR when the peer offered no protocols.
 * @return  MEMORY_ERROR on allocation failure.
 */
int wolfSSL_ALPN_GetPeerProtocol(WOLFSSL* ssl, char **list, word16 *listSz)
{
    int i, len;
    char *p;
    byte *s;

    if (ssl == NULL || list == NULL || listSz == NULL)
        return BAD_FUNC_ARG;

    if (ssl->alpn_peer_requested == NULL
        || ssl->alpn_peer_requested_length == 0)
        return BUFFER_ERROR;

    /* ssl->alpn_peer_requested are the original bytes sent in a ClientHello,
     * formatted as (len-byte chars+)+. To turn n protocols into a
     * comma-separated C string, one needs (n-1) commas and a final 0 byte
     * which has the same length as the original.
     * The returned length is the strlen() of the C string, so -1 of that. */
    *listSz = ssl->alpn_peer_requested_length-1;
    *list = p = (char *)XMALLOC(ssl->alpn_peer_requested_length, ssl->heap,
                                DYNAMIC_TYPE_TLSX);
    if (p == NULL)
        return MEMORY_ERROR;

    for (i = 0, s = ssl->alpn_peer_requested;
         i < ssl->alpn_peer_requested_length;
         p += len, i += len)
    {
        if (i)
            *p++ = ',';
        len = s[i++];
        /* guard against bad length bytes. */
        if (i + len > ssl->alpn_peer_requested_length) {
            XFREE(*list, ssl->heap, DYNAMIC_TYPE_TLSX);
            *list = NULL;
            return WOLFSSL_FAILURE;
        }
        XMEMCPY(p, s + i, (size_t)len);
    }
    *p = 0;

    return WOLFSSL_SUCCESS;
}


/* Free a peer protocol list returned by wolfSSL_ALPN_GetPeerProtocol().
 *
 * @param [in]      ssl   SSL/TLS object.
 * @param [in, out] list  Protocol list to free; set to NULL on return.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_ALPN_FreePeerProtocol(WOLFSSL* ssl, char **list)
{
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    XFREE(*list, ssl->heap, DYNAMIC_TYPE_TLSX);
    *list = NULL;

    return WOLFSSL_SUCCESS;
}

#endif /* HAVE_ALPN */

/* Secure Renegotiation */
#ifdef HAVE_SERVER_RENEGOTIATION_INFO

/* Enable the Secure Renegotiation extension on the object.
 *
 * Use of secure renegotiation is discouraged.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  Negative value on error.
 */
int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
#if defined(NO_TLS)
    (void)ssl;
#else
    if (ssl != NULL) {
        ret = TLSX_UseSecureRenegotiation(&ssl->extensions, ssl->heap);
    }
    else {
        ret = BAD_FUNC_ARG;
    }

    if (ret == WOLFSSL_SUCCESS) {
        TLSX* extension = TLSX_Find(ssl->extensions, TLSX_RENEGOTIATION_INFO);
        if (extension != NULL) {
            ssl->secure_renegotiation = (SecureRenegotiation*)extension->data;
        }
    }
#endif /* !NO_TLS */
    return ret;
}

/* Enable the Secure Renegotiation extension on the context.
 *
 * Use of secure renegotiation is discouraged.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_UseSecureRenegotiation(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->useSecureReneg = 1;
    return WOLFSSL_SUCCESS;
}

#ifdef HAVE_SECURE_RENEGOTIATION
/* Perform a secure renegotiation handshake on the object.
 *
 * User forced; use of secure renegotiation is discouraged.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  SECURE_RENEGOTIATION_E when renegotiation is not allowed.
 * @return  WOLFSSL_FATAL_ERROR on error.
 */
static int _Rehandshake(WOLFSSL* ssl)
{
    int ret;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (IsAtLeastTLSv1_3(ssl->version)) {
        WOLFSSL_MSG("Secure Renegotiation not supported in TLS 1.3");
        return SECURE_RENEGOTIATION_E;
    }

    if (ssl->secure_renegotiation == NULL) {
        WOLFSSL_MSG("Secure Renegotiation not forced on by user");
        return SECURE_RENEGOTIATION_E;
    }

    if (ssl->secure_renegotiation->enabled == 0) {
        WOLFSSL_MSG("Secure Renegotiation not enabled at extension level");
        return SECURE_RENEGOTIATION_E;
    }

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls && ssl->keys.dtls_epoch == 0xFFFF) {
        WOLFSSL_MSG("Secure Renegotiation not allowed. Epoch would wrap");
        return SECURE_RENEGOTIATION_E;
    }
#endif

    /* If the client started the renegotiation, the server will already
     * have processed the client's hello. */
    if (ssl->options.side != WOLFSSL_SERVER_END ||
        ssl->options.acceptState != ACCEPT_FIRST_REPLY_DONE) {

        if (ssl->options.handShakeState != HANDSHAKE_DONE) {
            if (!ssl->options.handShakeDone) {
                WOLFSSL_MSG("Can't renegotiate until initial "
                            "handshake complete");
                return SECURE_RENEGOTIATION_E;
            }
            else {
                WOLFSSL_MSG("Renegotiation already started. "
                            "Moving it forward.");
                ret = wolfSSL_negotiate(ssl);
                if (ret == WOLFSSL_SUCCESS)
                    ssl->secure_rene_count++;
                return ret;
            }
        }

        /* reset handshake states */
        ssl->options.sendVerify = 0;
        ssl->options.serverState = NULL_STATE;
        ssl->options.clientState = NULL_STATE;
        ssl->options.connectState  = CONNECT_BEGIN;
        ssl->options.acceptState   = ACCEPT_BEGIN_RENEG;
        ssl->options.handShakeState = NULL_STATE;
        ssl->options.processReply  = 0;  /* TODO, move states in internal.h */

        XMEMSET(&ssl->msgsReceived, 0, sizeof(ssl->msgsReceived));

        ssl->secure_renegotiation->cache_status = SCR_CACHE_NEEDED;

#if !defined(NO_WOLFSSL_SERVER) && !defined(WOLFSSL_NO_TLS12)
        if (ssl->options.side == WOLFSSL_SERVER_END) {
            ret = SendHelloRequest(ssl);
            if (ret != 0) {
                ssl->error = ret;
                return WOLFSSL_FATAL_ERROR;
            }
        }
#endif /* !NO_WOLFSSL_SERVER && !WOLFSSL_NO_TLS12 */

        ret = InitHandshakeHashes(ssl);
        if (ret != 0) {
            ssl->error = ret;
            return WOLFSSL_FATAL_ERROR;
        }
    }
    ret = wolfSSL_negotiate(ssl);
    if (ret == WOLFSSL_SUCCESS)
        ssl->secure_rene_count++;
    return ret;
}


/* Perform a secure renegotiation handshake on the object.
 *
 * User forced; use of secure renegotiation is discouraged.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl is NULL.
 * @return  Negative value on error.
 */
int wolfSSL_Rehandshake(WOLFSSL* ssl)
{
    int ret;
    WOLFSSL_ENTER("wolfSSL_Rehandshake");

    if (ssl == NULL)
        return WOLFSSL_FAILURE;

#ifdef HAVE_SESSION_TICKET
    ret = WOLFSSL_SUCCESS;
#endif

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        /* Reset option to send certificate verify. */
        ssl->options.sendVerify = 0;
        /* Reset resuming flag to do full secure handshake. */
        ssl->options.resuming = 0;
    }
    else {
        /* Reset resuming flag to do full secure handshake. */
        ssl->options.resuming = 0;
        #if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_CLIENT)
            /* Clearing the ticket. */
            ret = wolfSSL_UseSessionTicket(ssl);
        #endif
    }
    /* CLIENT/SERVER: Reset peer authentication for full secure handshake. */
    ssl->options.peerAuthGood = 0;

#ifdef HAVE_SESSION_TICKET
    if (ret == WOLFSSL_SUCCESS)
#endif
        ret = _Rehandshake(ssl);

    return ret;
}


#ifndef NO_WOLFSSL_CLIENT

/* Perform a secure resumption handshake on the object.
 *
 * Client side only. User forced; use of secure renegotiation is discouraged.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  WOLFSSL_FATAL_ERROR when called on a server.
 */
int wolfSSL_SecureResume(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_SecureResume");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        ssl->error = SIDE_ERROR;
        return WOLFSSL_FATAL_ERROR;
    }

    return _Rehandshake(ssl);
}

#endif /* NO_WOLFSSL_CLIENT */

#endif /* HAVE_SECURE_RENEGOTIATION */

/* Get whether secure renegotiation is enabled for the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  1 when secure renegotiation is enabled.
 * @return  0 when ssl is NULL or it is not enabled.
 */
long wolfSSL_SSL_get_secure_renegotiation_support(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_SSL_get_secure_renegotiation_support");

    return (ssl != NULL) && (ssl->secure_renegotiation != NULL) &&
           ssl->secure_renegotiation->enabled;
}

#endif /* HAVE_SECURE_RENEGOTIATION_INFO */

#if !defined(NO_WOLFSSL_CLIENT) && !defined(WOLFSSL_NO_TLS12) && \
    defined(WOLFSSL_HARDEN_TLS) && !defined(WOLFSSL_HARDEN_TLS_NO_SCR_CHECK)
/* Get whether the secure renegotiation check is enabled for the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  Non-zero when the check is enabled, 0 otherwise.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
WOLFSSL_API int wolfSSL_get_scr_check_enabled(const WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_get_scr_check_enabled");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return ssl->scr_check_enabled;
}

/* Set whether the secure renegotiation check is enabled for the object.
 *
 * @param [in] ssl      SSL/TLS object.
 * @param [in] enabled  Non-zero to enable the check, 0 to disable it.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
WOLFSSL_API int wolfSSL_set_scr_check_enabled(WOLFSSL* ssl, byte enabled)
{
    WOLFSSL_ENTER("wolfSSL_set_scr_check_enabled");

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->scr_check_enabled = !!enabled;
    return WOLFSSL_SUCCESS;
}
#endif

#if defined(HAVE_SESSION_TICKET)
/* Session Ticket */

#if !defined(NO_WOLFSSL_SERVER)
/* Disable use of session tickets with TLS 1.2 on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_NoTicketTLSv12(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->noTicketTls12 = 1;

    return WOLFSSL_SUCCESS;
}

/* Disable use of session tickets with TLS 1.2 on the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_NoTicketTLSv12(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.noTicketTls12 = 1;

    return WOLFSSL_SUCCESS;
}

/* Set the session ticket encryption callback on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] cb   Session ticket encryption callback.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx, SessionTicketEncCb cb)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->ticketEncCb = cb;

    return WOLFSSL_SUCCESS;
}

/* Set the session ticket lifetime hint, in seconds, on the context.
 *
 * @param [in] ctx   SSL/TLS context object.
 * @param [in] hint  Lifetime hint in seconds. No more than 604800 (7 days).
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL or hint is out of range.
 */
int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int hint)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    /* RFC8446 Section 4.6.1: Servers MUST NOT use any value greater than
     * 604800 seconds (7 days). */
    if (hint < 0 || hint > 604800)
        return BAD_FUNC_ARG;

    ctx->ticketHint = hint;

    return WOLFSSL_SUCCESS;
}

/* Set the user context passed to the session ticket encryption callback.
 *
 * @param [in] ctx      SSL/TLS context object.
 * @param [in] userCtx  User context for the ticket encryption callback.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void* userCtx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->ticketEncCtx = userCtx;

    return WOLFSSL_SUCCESS;
}

/* Get the user context passed to the session ticket encryption callback.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  User context on success.
 * @return  NULL when ctx is NULL.
 */
void* wolfSSL_CTX_get_TicketEncCtx(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->ticketEncCtx;
}

#ifdef WOLFSSL_TLS13
/* Set the maximum number of TLS 1.3 session tickets to send.
 *
 * @param [in] ctx        SSL/TLS context object.
 * @param [in] mxTickets  Maximum number of tickets to send.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx is NULL.
 */
int wolfSSL_CTX_set_num_tickets(WOLFSSL_CTX* ctx, size_t mxTickets)
{
    if (ctx == NULL)
        return WOLFSSL_FAILURE;

    ctx->maxTicketTls13 = (unsigned int)mxTickets;
    return WOLFSSL_SUCCESS;
}

/* Get the maximum number of TLS 1.3 session tickets to send.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  Maximum number of tickets to send, or 0 when ctx is NULL.
 */
size_t wolfSSL_CTX_get_num_tickets(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return 0;

    return (size_t)ctx->maxTicketTls13;
}
#endif /* WOLFSSL_TLS13 */
#endif /* !NO_WOLFSSL_SERVER */

#if !defined(NO_WOLFSSL_CLIENT)
/* Enable use of the session ticket extension on the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  Negative value on error.
 */
int wolfSSL_UseSessionTicket(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSessionTicket(&ssl->extensions, NULL, ssl->heap);
}

/* Enable use of the session ticket extension on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 * @return  Negative value on error.
 */
int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSessionTicket(&ctx->extensions, NULL, ctx->heap);
}

/* Get the session ticket stored on the object.
 *
 * When buf is NULL and *bufSz is 0, the length required is returned in bufSz.
 *
 * @param [in]      ssl    SSL/TLS object.
 * @param [out]     buf    Buffer to hold the ticket. May be NULL for length.
 * @param [in, out] bufSz  In: size of buffer. Out: length of ticket.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  LENGTH_ONLY_E when buf is NULL and bufSz has been set.
 * @return  BAD_FUNC_ARG when ssl or bufSz is NULL.
 */
int wolfSSL_get_SessionTicket(WOLFSSL* ssl, byte* buf, word32* bufSz)
{
    if (ssl == NULL || bufSz == NULL)
        return BAD_FUNC_ARG;

    if (*bufSz == 0 && buf == NULL) {
        *bufSz = ssl->session->ticketLen;
        return LENGTH_ONLY_E;
    }

    if (buf == NULL)
        return BAD_FUNC_ARG;

    if (ssl->session->ticketLen <= *bufSz) {
        XMEMCPY(buf, ssl->session->ticket, ssl->session->ticketLen);
        *bufSz = ssl->session->ticketLen;
    }
    else
        *bufSz = 0;

    return WOLFSSL_SUCCESS;
}

/* Set the session ticket to use on the object.
 *
 * @param [in] ssl    SSL/TLS object.
 * @param [in] buf    Ticket data, may be NULL when bufSz is 0.
 * @param [in] bufSz  Length of ticket data in bytes.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL or buf is NULL with bufSz > 0.
 * @return  MEMORY_ERROR on allocation failure.
 */
int wolfSSL_set_SessionTicket(WOLFSSL* ssl, const byte* buf,
                                          word32 bufSz)
{
    if (ssl == NULL || (buf == NULL && bufSz > 0))
        return BAD_FUNC_ARG;

    if (bufSz > 0) {
        /* Ticket will fit into static ticket */
        if (bufSz <= SESSION_TICKET_LEN) {
            if (ssl->session->ticketLenAlloc > 0) {
                XFREE(ssl->session->ticket, ssl->session->heap,
                      DYNAMIC_TYPE_SESSION_TICK);
                ssl->session->ticketLenAlloc = 0;
                ssl->session->ticket = ssl->session->staticTicket;
            }
        }
        else { /* Ticket requires dynamic ticket storage */
            /* is dyn buffer big enough */
            if (ssl->session->ticketLen < bufSz) {
                if (ssl->session->ticketLenAlloc > 0) {
                    XFREE(ssl->session->ticket, ssl->session->heap,
                          DYNAMIC_TYPE_SESSION_TICK);
                }
                ssl->session->ticket = (byte*)XMALLOC(bufSz, ssl->session->heap,
                        DYNAMIC_TYPE_SESSION_TICK);
                if(ssl->session->ticket == NULL) {
                    ssl->session->ticket = ssl->session->staticTicket;
                    ssl->session->ticketLenAlloc = 0;
                    return MEMORY_ERROR;
                }
                ssl->session->ticketLenAlloc = (word16)bufSz;
            }
        }
        XMEMCPY(ssl->session->ticket, buf, bufSz);
    }
    ssl->session->ticketLen = (word16)bufSz;

    return WOLFSSL_SUCCESS;
}


/* Set the session ticket callback and user context on the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] cb   Session ticket callback.
 * @param [in] ctx  User context passed to the callback.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_set_SessionTicket_cb(WOLFSSL* ssl,
                                 CallbackSessionTicket cb, void* ctx)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->session_ticket_cb = cb;
    ssl->session_ticket_ctx = ctx;

    return WOLFSSL_SUCCESS;
}
#endif /* !NO_WOLFSSL_CLIENT */

#endif /* HAVE_SESSION_TICKET */


#ifdef HAVE_EXTENDED_MASTER
#ifndef NO_WOLFSSL_CLIENT

/* Disable the Extended Master Secret extension on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ctx is NULL.
 */
int wolfSSL_CTX_DisableExtendedMasterSecret(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->haveEMS = 0;

    return WOLFSSL_SUCCESS;
}


/* Disable the Extended Master Secret extension on the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 */
int wolfSSL_DisableExtendedMasterSecret(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ssl->options.haveEMS = 0;

    return WOLFSSL_SUCCESS;
}

#endif
#endif

#endif /* !NO_TLS */
/* ---- OpenSSL-compatibility TLS extension APIs (moved from ssl.c) ---- */

#ifdef OPENSSL_EXTRA

#ifdef HAVE_PK_CALLBACKS
/* Set the debug argument passed to the logging callback on the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] arg  Debug argument.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl is NULL.
 */
long wolfSSL_set_tlsext_debug_arg(WOLFSSL* ssl, void *arg)
{
    if (ssl == NULL) {
        return WOLFSSL_FAILURE;
    }

    ssl->loggingCtx = arg;
    return WOLFSSL_SUCCESS;
}
#endif /* HAVE_PK_CALLBACKS */

#ifndef NO_WOLFSSL_STUB
/* Get the certificate status request extensions on the object.
 *
 * Not implemented - stub for OpenSSL compatibility.
 *
 * @param [in] s    SSL/TLS object.
 * @param [in] arg  Ignored.
 * @return  WOLFSSL_FAILURE always.
 */
long wolfSSL_get_tlsext_status_exts(WOLFSSL *s, void *arg)
{
    (void)s;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_get_tlsext_status_exts");
    return WOLFSSL_FAILURE;
}
#endif

/* Set the certificate status request extensions on the object.
 *
 * Not implemented - stub for OpenSSL compatibility.
 *
 * @param [in] s    SSL/TLS object.
 * @param [in] arg  Ignored.
 * @return  WOLFSSL_FAILURE always.
 */
#ifndef NO_WOLFSSL_STUB
long wolfSSL_set_tlsext_status_exts(WOLFSSL *s, void *arg)
{
    (void)s;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_set_tlsext_status_exts");
    return WOLFSSL_FAILURE;
}
#endif

/* Get the certificate status request responder ids on the object.
 *
 * Not implemented - stub for OpenSSL compatibility.
 *
 * @param [in] s    SSL/TLS object.
 * @param [in] arg  Ignored.
 * @return  WOLFSSL_FAILURE always.
 */
#ifndef NO_WOLFSSL_STUB
long wolfSSL_get_tlsext_status_ids(WOLFSSL *s, void *arg)
{
    (void)s;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_get_tlsext_status_ids");
    return WOLFSSL_FAILURE;
}
#endif

/* Set the certificate status request responder ids on the object.
 *
 * Not implemented - stub for OpenSSL compatibility.
 *
 * @param [in] s    SSL/TLS object.
 * @param [in] arg  Ignored.
 * @return  WOLFSSL_FAILURE always.
 */
#ifndef NO_WOLFSSL_STUB
long wolfSSL_set_tlsext_status_ids(WOLFSSL *s, void *arg)
{
    (void)s;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_set_tlsext_status_ids");
    return WOLFSSL_FAILURE;
}
#endif

#ifdef HAVE_MAX_FRAGMENT
#if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_TLS)
/* Set the Maximum Fragment Length extension on the context.
 *
 * @param [in] c     SSL/TLS context object.
 * @param [in] mode  Maximum fragment length mode, e.g. WOLFSSL_MFL_2_9.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when c is NULL or mode is out of range.
 */
int wolfSSL_CTX_set_tlsext_max_fragment_length(WOLFSSL_CTX *c,
                                               unsigned char mode)
{
    if (c == NULL || (mode < WOLFSSL_MFL_2_9 || mode > WOLFSSL_MFL_2_12 ))
        return BAD_FUNC_ARG;

    return wolfSSL_CTX_UseMaxFragment(c, mode);
}
/* Set the Maximum Fragment Length extension on the object.
 *
 * @param [in] s     SSL/TLS object.
 * @param [in] mode  Maximum fragment length mode, e.g. WOLFSSL_MFL_2_9.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when s is NULL or mode is out of range.
 */
int wolfSSL_set_tlsext_max_fragment_length(WOLFSSL *s, unsigned char mode)
{
    if (s == NULL || (mode < WOLFSSL_MFL_2_9 || mode > WOLFSSL_MFL_2_12 ))
        return BAD_FUNC_ARG;

    return wolfSSL_UseMaxFragment(s, mode);
}
#endif /* !NO_WOLFSSL_CLIENT && !NO_TLS */
#endif /* HAVE_MAX_FRAGMENT */

/* Set the signature algorithms list on the context.
 *
 * @param [in] ctx   SSL/TLS context object.
 * @param [in] list  Colon-separated list of <public key>+<digest> algorithms.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx or list is NULL or on error.
 */
int wolfSSL_CTX_set1_sigalgs_list(WOLFSSL_CTX* ctx, const char* list)
{
    WOLFSSL_MSG("wolfSSL_CTX_set1_sigalg_list");

    if (ctx == NULL || list == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    if (AllocateCtxSuites(ctx) != 0)
        return WOLFSSL_FAILURE;

    return SetSuitesHashSigAlgo(ctx->suites, list);
}

/* Set the signature algorithms list on the object.
 *
 * @param [in] ssl   SSL/TLS object.
 * @param [in] list  Colon-separated list of <public key>+<digest> algorithms.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl or list is NULL or on error.
 */
int wolfSSL_set1_sigalgs_list(WOLFSSL* ssl, const char* list)
{
    WOLFSSL_MSG("wolfSSL_set1_sigalg_list");

    if (ssl == NULL || list == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FAILURE;
    }

    if (AllocateSuites(ssl) != 0)
        return WOLFSSL_FAILURE;

    return SetSuitesHashSigAlgo(ssl->suites, list);
}

#ifdef HAVE_ECC

#if defined(WOLFSSL_TLS13) && defined(HAVE_SUPPORTED_CURVES)
/* Set the supported groups list, by name, on the context.
 *
 * @param [in] ctx   SSL/TLS context object.
 * @param [in] list  Colon-separated list of group names.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx or list is NULL or on error.
 */
int wolfSSL_CTX_set1_groups_list(WOLFSSL_CTX *ctx, const char *list)
{
    if (!ctx || !list) {
        return WOLFSSL_FAILURE;
    }

    return set_curves_list(NULL, ctx, list, 0);
}

/* Set the supported groups list, by name, on the object.
 *
 * @param [in] ssl   SSL/TLS object.
 * @param [in] list  Colon-separated list of group names.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl or list is NULL or on error.
 */
int wolfSSL_set1_groups_list(WOLFSSL *ssl, const char *list)
{
    if (!ssl || !list) {
        return WOLFSSL_FAILURE;
    }

    return set_curves_list(ssl, NULL, list, 0);
}
#endif /* WOLFSSL_TLS13 */

#endif /* HAVE_ECC */

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)

#ifdef HAVE_SNI
/* Set the SNI host name extension on the object.
 *
 * @param [in] ssl        SSL/TLS object.
 * @param [in] host_name  Host name string.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  BAD_FUNC_ARG when ssl is NULL.
 * @return  Negative value on error.
 */
int wolfSSL_set_tlsext_host_name(WOLFSSL* ssl, const char* host_name)
{
    int ret;
    WOLFSSL_ENTER("wolfSSL_set_tlsext_host_name");
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host_name,
        (word16)XSTRLEN(host_name));
    WOLFSSL_LEAVE("wolfSSL_set_tlsext_host_name", ret);
    return ret;
}

#ifndef NO_WOLFSSL_SERVER
/* Get the SNI host name requested for the object.
 *
 * May be called by a server to get the accepted name or by a client to get
 * the requested name.
 *
 * @param [in] ssl   SSL/TLS object.
 * @param [in] type  SNI type.
 * @return  Requested server name on success.
 * @return  NULL when ssl is NULL or no name is set.
 */
const char * wolfSSL_get_servername(WOLFSSL* ssl, byte type)
{
    void * serverName = NULL;
    if (ssl == NULL)
        return NULL;
    TLSX_SNI_GetRequest(ssl->extensions, type, &serverName,
            !wolfSSL_is_server(ssl));
    return (const char *)serverName;
}
#endif

#endif /* HAVE_SNI */

#ifdef HAVE_SNI
/* Set the SNI receive callback on the context.
 *
 * Compatibility function; consider using wolfSSL_CTX_set_servername_callback().
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] cb   SNI receive callback.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx is NULL.
 */
int wolfSSL_CTX_set_tlsext_servername_callback(WOLFSSL_CTX* ctx,
                                               CallbackSniRecv cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_tlsext_servername_callback");
    if (ctx) {
        ctx->sniRecvCb = cb;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}

#endif /* HAVE_SNI */

#endif /* OPENSSL_ALL || OPENSSL_EXTRA */

#ifdef HAVE_SNI

/* Set the SNI receive callback on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] cb   SNI receive callback.
 */
void wolfSSL_CTX_set_servername_callback(WOLFSSL_CTX* ctx, CallbackSniRecv cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_servername_callback");

    if (ctx != NULL) {
        ctx->sniRecvCb = cb;
    }
}


/* Set the user argument passed to the SNI receive callback on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] arg  User argument for the SNI receive callback.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx is NULL.
 */
int wolfSSL_CTX_set_servername_arg(WOLFSSL_CTX* ctx, void* arg)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_servername_arg");
    if (ctx) {
        ctx->sniRecvCbArg = arg;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}

#endif /* HAVE_SNI */

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY) \
    || defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY)

#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER)
/* Expected return values from implementations of OpenSSL ticket key callback.
 */
#define TICKET_KEY_CB_RET_FAILURE    (-1)
#define TICKET_KEY_CB_RET_NOT_FOUND   0
#define TICKET_KEY_CB_RET_OK          1
#define TICKET_KEY_CB_RET_RENEW       2

/* Encrypt the ticket data in place and compute the HMAC over it.
 *
 * @param [in]      evpCtx        Cipher context initialized by the callback.
 * @param [in]      hmacCtx       HMAC context initialized by the callback.
 * @param [in, out] encTicket     Ticket data, encrypted in place.
 * @param [in]      encTicketLen  Length of the plaintext ticket data in bytes.
 * @param [in]      encSz         Capacity of the ticket buffer in bytes.
 * @param [out]     mac           HMAC of the encrypted data.
 * @param [out]     outSz         Length of the encrypted data in bytes.
 * @return  1 on success.
 * @return  0 on error.
 */
static int wolfssl_ticket_key_enc(WOLFSSL_EVP_CIPHER_CTX* evpCtx,
        WOLFSSL_HMAC_CTX* hmacCtx, unsigned char* encTicket, int encTicketLen,
        int encSz, unsigned char* mac, int* outSz)
{
    int ret = 1;
    int len = 0;
    int totalSz = 0;
    unsigned int mdSz = 0;

    /* Encrypt in place. */
    if (!wolfSSL_EVP_CipherUpdate(evpCtx, encTicket, &len, encTicket,
            encTicketLen)) {
        ret = 0;
    }
    if (ret == 1) {
        totalSz = len;
        /* Encrypted data must fit in the output buffer. */
        if (totalSz > encSz) {
            ret = 0;
        }
    }
    if ((ret == 1) &&
            (!wolfSSL_EVP_EncryptFinal(evpCtx, &encTicket[len], &len))) {
        ret = 0;
    }
    if (ret == 1) {
        /* Total length of encrypted data. */
        totalSz += len;
        if (totalSz > encSz) {
            ret = 0;
        }
    }
    /* HMAC the encrypted data into the parameter 'mac'. */
    if ((ret == 1) && (!wolfSSL_HMAC_Update(hmacCtx, encTicket, totalSz))) {
        ret = 0;
    }
    if ((ret == 1) && (!wolfSSL_HMAC_Final(hmacCtx, mac, &mdSz))) {
        ret = 0;
    }
    if (ret == 1) {
        *outSz = totalSz;
    }

    return ret;
}

/* Verify the ticket HMAC then decrypt the ticket data in place.
 *
 * @param [in]      evpCtx        Cipher context initialized by the callback.
 * @param [in]      hmacCtx       HMAC context initialized by the callback.
 * @param [in, out] encTicket     Ticket data, decrypted in place.
 * @param [in]      encTicketLen  Length of the encrypted ticket data in bytes.
 * @param [in]      mac           Expected HMAC of the encrypted data.
 * @param [out]     outSz         Length of the decrypted data in bytes.
 * @return  1 on success.
 * @return  0 on error or when the HMAC does not match.
 */
static int wolfssl_ticket_key_dec(WOLFSSL_EVP_CIPHER_CTX* evpCtx,
        WOLFSSL_HMAC_CTX* hmacCtx, unsigned char* encTicket, int encTicketLen,
        const unsigned char* mac, int* outSz)
{
    int ret = 1;
    int len = 0;
    int totalSz = 0;
    unsigned int mdSz = 0;
    byte digest[WC_MAX_DIGEST_SIZE];

    /* HMAC the encrypted data and compare it to the passed in data. */
    if (!wolfSSL_HMAC_Update(hmacCtx, encTicket, encTicketLen)) {
        ret = 0;
    }
    if ((ret == 1) && (!wolfSSL_HMAC_Final(hmacCtx, digest, &mdSz))) {
        ret = 0;
    }
    if ((ret == 1) && (ConstantCompare(mac, digest, (int)mdSz) != 0)) {
        ret = 0;
    }
    /* Decrypt the ticket data in place. */
    if ((ret == 1) &&
            (!wolfSSL_EVP_CipherUpdate(evpCtx, encTicket, &len, encTicket,
                encTicketLen))) {
        ret = 0;
    }
    if (ret == 1) {
        totalSz = len;
        /* Decrypted data must fit in the buffer. */
        if (totalSz > encTicketLen) {
            ret = 0;
        }
    }
    if ((ret == 1) &&
            (!wolfSSL_EVP_DecryptFinal(evpCtx, &encTicket[len], &len))) {
        ret = 0;
    }
    if (ret == 1) {
        /* Total length of decrypted data. */
        totalSz += len;
        if (totalSz > encTicketLen) {
            ret = 0;
        }
    }
    if (ret == 1) {
        *outSz = totalSz;
    }

    return ret;
}

/* Encrypt or decrypt a session ticket using the OpenSSL ticket key callback.
 *
 * Wraps the application's OpenSSL-style callback that initializes the cipher
 * and HMAC.
 *
 * @param [in]      ssl           SSL/TLS object.
 * @param [in]      keyName       Key name identifying the key to use.
 * @param [in]      iv            IV to use.
 * @param [in, out] mac          MAC of the encrypted data.
 * @param [in]      enc           1 to encrypt the ticket, 0 to decrypt.
 * @param [in, out] encTicket     Ticket data, encrypted/decrypted in place.
 * @param [in]      encTicketLen  Length of the ticket data in bytes.
 * @param [out]     encLen        Output length of the ticket data.
 * @param [in]      ctx           Ignored. Application specific data.
 * @return  WOLFSSL_TICKET_RET_OK on success.
 * @return  WOLFSSL_TICKET_RET_CREATE when a new ticket is required.
 * @return  WOLFSSL_TICKET_RET_FATAL on error.
 */
static int wolfSSL_TicketKeyCb(WOLFSSL* ssl,
        unsigned char keyName[WOLFSSL_TICKET_NAME_SZ],
        unsigned char iv[WOLFSSL_TICKET_IV_SZ],
        unsigned char mac[WOLFSSL_TICKET_MAC_SZ],
        int enc, unsigned char* encTicket,
        int encTicketLen, int* encLen, void* ctx)
{
    WC_DECLARE_VAR(evpCtx, WOLFSSL_EVP_CIPHER_CTX, 1, 0);
    int ret = WOLFSSL_TICKET_RET_OK;

    (void)ctx;

    WOLFSSL_ENTER("wolfSSL_TicketKeyCb");

    if ((ssl == NULL) || (ssl->ctx == NULL) ||
            (ssl->ctx->ticketEncWrapCb == NULL)) {
        WOLFSSL_MSG("Bad parameter");
        ret = WOLFSSL_TICKET_RET_FATAL;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret == WOLFSSL_TICKET_RET_OK) {
        evpCtx = (WOLFSSL_EVP_CIPHER_CTX *)XMALLOC(sizeof(*evpCtx), ssl->heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (evpCtx == NULL) {
            WOLFSSL_MSG("out of memory");
            ret = WOLFSSL_TICKET_RET_FATAL;
        }
    }
#endif

    if (ret == WOLFSSL_TICKET_RET_OK) {
        WOLFSSL_HMAC_CTX hmacCtx;

        /* Initialize the cipher and HMAC. */
        wolfSSL_EVP_CIPHER_CTX_init(evpCtx);

        if (wolfSSL_HMAC_CTX_Init(&hmacCtx) != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("wolfSSL_HMAC_CTX_Init error");
            ret = WOLFSSL_TICKET_RET_FATAL;
        }

        if (ret == WOLFSSL_TICKET_RET_OK) {
            int res;
            int totalSz = 0;

            res = ssl->ctx->ticketEncWrapCb(ssl, keyName, iv, evpCtx, &hmacCtx,
                    enc);
            if ((res != TICKET_KEY_CB_RET_OK) &&
                    (res != TICKET_KEY_CB_RET_RENEW)) {
                WOLFSSL_MSG("Ticket callback error");
                ret = WOLFSSL_TICKET_RET_FATAL;
            }

            if (ret == WOLFSSL_TICKET_RET_OK) {
                if (wolfSSL_HMAC_size(&hmacCtx) > WOLFSSL_TICKET_MAC_SZ) {
                    WOLFSSL_MSG("Ticket cipher MAC size error");
                    ret = WOLFSSL_TICKET_RET_FATAL;
                }
            }

            if (ret == WOLFSSL_TICKET_RET_OK) {
                if (enc) {
                    if (!wolfssl_ticket_key_enc(evpCtx, &hmacCtx, encTicket,
                            encTicketLen, *encLen, mac, &totalSz)) {
                        ret = WOLFSSL_TICKET_RET_FATAL;
                    }
                }
                else {
                    if (!wolfssl_ticket_key_dec(evpCtx, &hmacCtx, encTicket,
                            encTicketLen, mac, &totalSz)) {
                        ret = WOLFSSL_TICKET_RET_FATAL;
                    }
                }
            }

            if (ret == WOLFSSL_TICKET_RET_OK) {
                *encLen = totalSz;

                if ((res == TICKET_KEY_CB_RET_RENEW) &&
                        (!IsAtLeastTLSv1_3(ssl->version)) && (!enc)) {
                    ret = WOLFSSL_TICKET_RET_CREATE;
                }
                else {
                    ret = WOLFSSL_TICKET_RET_OK;
                }
            }

            (void)wc_HmacFree(&hmacCtx.hmac);
        }
        (void)wolfSSL_EVP_CIPHER_CTX_cleanup(evpCtx);
        WC_FREE_VAR_EX(evpCtx, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

/* Set the OpenSSL-style session ticket key callback on the context.
 *
 * Installs a wrapper as the ticket encryption callback.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] cb   OpenSSL session ticket key callback.
 * @return  WOLFSSL_SUCCESS on success.
 */
int wolfSSL_CTX_set_tlsext_ticket_key_cb(WOLFSSL_CTX *ctx, ticketCompatCb cb)
{

    /* Set the ticket encryption callback to be a wrapper around OpenSSL
     * callback.
     */
    ctx->ticketEncCb = wolfSSL_TicketKeyCb;
    ctx->ticketEncWrapCb = cb;

    return WOLFSSL_SUCCESS;
}

#endif /* HAVE_SESSION_TICKET */

#endif /* OPENSSL_ALL || WOLFSSL_NGINX || WOLFSSL_HAPROXY ||
    OPENSSL_EXTRA || HAVE_LIGHTY */

#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB) && \
    !defined(NO_WOLFSSL_SERVER)
/* Serialize the session ticket encryption keys.
 *
 * @param [in]  ctx     SSL/TLS context object.
 * @param [in]  keys    Buffer to hold session ticket keys.
 * @param [in]  keylen  Length of buffer.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx is NULL, keys is NULL or keylen is not the
 *          correct length.
 */
long wolfSSL_CTX_get_tlsext_ticket_keys(WOLFSSL_CTX *ctx,
     unsigned char *keys, int keylen)
{
    if (ctx == NULL || keys == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (keylen != WOLFSSL_TICKET_KEYS_SZ) {
        return WOLFSSL_FAILURE;
    }

    XMEMCPY(keys, ctx->ticketKeyCtx.name, WOLFSSL_TICKET_NAME_SZ);
    keys += WOLFSSL_TICKET_NAME_SZ;
    XMEMCPY(keys, ctx->ticketKeyCtx.key[0], WOLFSSL_TICKET_KEY_SZ);
    keys += WOLFSSL_TICKET_KEY_SZ;
    XMEMCPY(keys, ctx->ticketKeyCtx.key[1], WOLFSSL_TICKET_KEY_SZ);
    keys += WOLFSSL_TICKET_KEY_SZ;
    c32toa(ctx->ticketKeyCtx.expirary[0], keys);
    keys += OPAQUE32_LEN;
    c32toa(ctx->ticketKeyCtx.expirary[1], keys);

    return WOLFSSL_SUCCESS;
}

/* Deserialize the session ticket encryption keys.
 *
 * @param [in]  ctx     SSL/TLS context object.
 * @param [in]  keys    Session ticket keys.
 * @param [in]  keylen  Length of data.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx is NULL, keys is NULL or keylen is not the
 *          correct length.
 */
long wolfSSL_CTX_set_tlsext_ticket_keys(WOLFSSL_CTX *ctx,
     const void *keys_vp, int keylen)
{
    const byte* keys = (const byte*)keys_vp;
    if (ctx == NULL || keys == NULL) {
        return WOLFSSL_FAILURE;
    }
    if (keylen != WOLFSSL_TICKET_KEYS_SZ) {
        return WOLFSSL_FAILURE;
    }

    XMEMCPY(ctx->ticketKeyCtx.name, keys, WOLFSSL_TICKET_NAME_SZ);
    keys += WOLFSSL_TICKET_NAME_SZ;
    XMEMCPY(ctx->ticketKeyCtx.key[0], keys, WOLFSSL_TICKET_KEY_SZ);
    keys += WOLFSSL_TICKET_KEY_SZ;
    XMEMCPY(ctx->ticketKeyCtx.key[1], keys, WOLFSSL_TICKET_KEY_SZ);
    keys += WOLFSSL_TICKET_KEY_SZ;
    ato32(keys, &ctx->ticketKeyCtx.expirary[0]);
    keys += OPAQUE32_LEN;
    ato32(keys, &ctx->ticketKeyCtx.expirary[1]);

    return WOLFSSL_SUCCESS;
}
#endif

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_QUIC)
#ifdef HAVE_ALPN
/* Get the ALPN protocol selected for the object.
 *
 * @param [in]  ssl   SSL/TLS object.
 * @param [out] data  Selected protocol data.
 * @param [out] len   Length of the protocol data in bytes.
 */
void wolfSSL_get0_alpn_selected(const WOLFSSL *ssl, const unsigned char **data,
                                unsigned int *len)
{
    word16 nameLen = 0;

    if ((ssl != NULL) && (data != NULL) && (len != NULL)) {
        TLSX_ALPN_GetRequest(ssl->extensions, (void **)data, &nameLen);
        *len = nameLen;
    }
}

/* Determine whether a protocol appears in the client's protocol list.
 *
 * The client's list is in wire format: each entry is a length byte followed
 * by that many protocol-name bytes.
 *
 * @param [in]  proto        Protocol name to look for.
 * @param [in]  protoLen     Length of the protocol name in bytes.
 * @param [in]  clientNames  Client's protocol list.
 * @param [in]  clientLen    Length of the client's list in bytes.
 * @return  1 when the protocol is in the list.
 * @return  0 when the protocol is not in the list.
 */
static int wolfssl_protocol_in_list(const unsigned char* proto, byte protoLen,
    const unsigned char* clientNames, unsigned int clientLen)
{
    unsigned int j;
    byte lenClient;
    int found = 0;

    /* Compare against each of the client's length-prefixed names. */
    for (j = 0; j < clientLen; j += lenClient) {
        lenClient = clientNames[j++];
        if ((lenClient == 0) || (j + lenClient > clientLen)) {
            break;
        }

        if ((protoLen == lenClient) &&
                (XMEMCMP(proto, clientNames + j, protoLen) == 0)) {
            found = 1;
            break;
        }
    }

    return found;
}

/* Select the next protocol from the peer's list that matches the client's.
 *
 * On no overlap, the first client protocol is selected.
 *
 * @param [out] out          Selected protocol data.
 * @param [out] outLen        Length of the selected protocol in bytes.
 * @param [in]  in            Peer's protocol list.
 * @param [in]  inLen         Length of the peer's list in bytes.
 * @param [in]  clientNames   Client's protocol list.
 * @param [in]  clientLen     Length of the client's list in bytes.
 * @return  WOLFSSL_NPN_NEGOTIATED when a match was found.
 * @return  WOLFSSL_NPN_NO_OVERLAP when no match was found.
 * @return  WOLFSSL_NPN_UNSUPPORTED when an argument is NULL.
 */
int wolfSSL_select_next_proto(unsigned char **out, unsigned char *outLen,
    const unsigned char *in, unsigned int inLen,
    const unsigned char *clientNames, unsigned int clientLen)
{
    unsigned int i;
    byte lenIn;
    int ret = WOLFSSL_NPN_NO_OVERLAP;

    if ((out == NULL) || (outLen == NULL) || (in == NULL) ||
            (clientNames == NULL)) {
        ret = WOLFSSL_NPN_UNSUPPORTED;
    }
    else {
        /* Walk the peer's list; each entry is a length byte then that many
         * protocol-name bytes. */
        for (i = 0; i < inLen; i += lenIn) {
            lenIn = in[i++];
            /* Stop on an empty entry or one that runs past the buffer. */
            if ((lenIn == 0) || (i + lenIn > inLen)) {
                break;
            }
            /* Select this peer protocol if the client also offered it. */
            if (wolfssl_protocol_in_list(in + i, lenIn, clientNames,
                    clientLen)) {
                *out = (unsigned char *)(in + i);
                *outLen = lenIn;
                ret = WOLFSSL_NPN_NEGOTIATED;
                break;
            }
        }

        if (ret != WOLFSSL_NPN_NEGOTIATED) {
            /* No overlap: fall back to the client's first protocol. */
            if ((clientLen > 0) &&
                    ((unsigned int)clientNames[0] + 1 <= clientLen)) {
                *out = (unsigned char *)clientNames + 1;
                *outLen = clientNames[0];
            }
            else {
                *out = (unsigned char *)clientNames;
                *outLen = 0;
            }
            ret = WOLFSSL_NPN_NO_OVERLAP;
        }
    }

    return ret;
}

/* Set the ALPN selection callback on the object.
 *
 * @param [in] ssl  SSL/TLS object.
 * @param [in] cb   ALPN selection callback.
 * @param [in] arg  User argument passed to the callback.
 */
void wolfSSL_set_alpn_select_cb(WOLFSSL *ssl,
    int (*cb)(WOLFSSL *ssl, const unsigned char **out, unsigned char *outlen,
              const unsigned char *in, unsigned int inlen, void *arg),
    void *arg)
{
    if (ssl != NULL) {
        ssl->alpnSelect = cb;
        ssl->alpnSelectArg = arg;
    }
}

/* Set the ALPN selection callback on the context.
 *
 * @param [in] ctx  SSL/TLS context object.
 * @param [in] cb   ALPN selection callback.
 * @param [in] arg  User argument passed to the callback.
 */
void wolfSSL_CTX_set_alpn_select_cb(WOLFSSL_CTX *ctx,
    int (*cb)(WOLFSSL *ssl, const unsigned char **out, unsigned char *outlen,
              const unsigned char *in, unsigned int inlen, void *arg),
    void *arg)
{
    if (ctx != NULL) {
        ctx->alpnSelect = cb;
        ctx->alpnSelectArg = arg;
    }
}

/* Set the NPN advertised-protocols callback on the context.
 *
 * Not implemented - stub for OpenSSL compatibility.
 *
 * @param [in] s    SSL/TLS context object.
 * @param [in] cb   NPN advertised-protocols callback.
 * @param [in] arg  User argument passed to the callback.
 */
void wolfSSL_CTX_set_next_protos_advertised_cb(WOLFSSL_CTX *s,
    int (*cb)(WOLFSSL *ssl, const unsigned char **out, unsigned int *outlen,
              void *arg), void *arg)
{
    (void)s;
    (void)cb;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_CTX_set_next_protos_advertised_cb");
}

/* Set the NPN protocol-selection callback on the context.
 *
 * Not implemented - stub for OpenSSL compatibility.
 *
 * @param [in] s    SSL/TLS context object.
 * @param [in] cb   NPN protocol-selection callback.
 * @param [in] arg  User argument passed to the callback.
 */
void wolfSSL_CTX_set_next_proto_select_cb(WOLFSSL_CTX *s,
    int (*cb)(WOLFSSL *ssl, unsigned char **out, unsigned char *outlen,
              const unsigned char *in, unsigned int inlen, void *arg),
    void *arg)
{
    (void)s;
    (void)cb;
    (void)arg;
    WOLFSSL_STUB("wolfSSL_CTX_set_next_proto_select_cb");
}

/* Get the NPN protocol negotiated for the object.
 *
 * Not implemented - stub for OpenSSL compatibility.
 *
 * @param [in]  s     SSL/TLS object.
 * @param [out] data  Negotiated protocol data.
 * @param [out] len   Length of the protocol data in bytes.
 */
void wolfSSL_get0_next_proto_negotiated(const WOLFSSL *s,
    const unsigned char **data, unsigned *len)
{
    (void)s;
    (void)data;
    (void)len;
    WOLFSSL_STUB("wolfSSL_get0_next_proto_negotiated");
}
#endif /* HAVE_ALPN */

#endif /* WOLFSSL_NGINX  / WOLFSSL_HAPROXY */

#if defined(OPENSSL_EXTRA) || defined(HAVE_CURL)

/* Determine whether an elliptic curve is disabled for the object.
 *
 * @param [in] ssl       SSL/TLS object.
 * @param [in] curve_id  Curve identifier.
 * @return  1 when the curve is disabled or out of range.
 * @return  0 when the curve is enabled or is an FFDHE group.
 */
int wolfSSL_curve_is_disabled(const WOLFSSL* ssl, word16 curve_id)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_curve_is_disabled");
    WOLFSSL_MSG_EX("wolfSSL_curve_is_disabled checking for %d", curve_id);

    /* (curve_id >= WOLFSSL_FFDHE_START) - DH parameters are never disabled. */
    if (curve_id < WOLFSSL_FFDHE_START) {
        if (curve_id > WOLFSSL_ECC_MAX_AVAIL) {
            WOLFSSL_MSG("Curve id out of supported range");
            /* Disabled if not in valid range. */
            ret = 1;
        }
        else if (curve_id >= 32) {
            /* 0 is for invalid and 1-14 aren't used otherwise. */
            ret = (ssl->disabledCurves & (1U << (curve_id - 32))) != 0;
        }
        else {
            ret = (ssl->disabledCurves & (1U << curve_id)) != 0;
        }
    }

    WOLFSSL_LEAVE("wolfSSL_curve_is_disabled", ret);
    return ret;
}

#if (defined(HAVE_ECC) || \
    defined(HAVE_CURVE25519) || defined(HAVE_CURVE448))

/* Set the supported curves list, by name, on the context.
 *
 * @param [in] ctx    SSL/TLS context object.
 * @param [in] names  Colon-separated list of curve names.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ctx or names is NULL or on error.
 */
int wolfSSL_CTX_set1_curves_list(WOLFSSL_CTX* ctx, const char* names)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set1_curves_list");
    if (ctx == NULL || names == NULL) {
        WOLFSSL_MSG("ctx or names was NULL");
        return WOLFSSL_FAILURE;
    }
    return set_curves_list(NULL, ctx, names, 1);
}

/* Set the supported curves list, by name, on the object.
 *
 * @param [in] ssl    SSL/TLS object.
 * @param [in] names  Colon-separated list of curve names.
 * @return  WOLFSSL_SUCCESS on success.
 * @return  WOLFSSL_FAILURE when ssl or names is NULL or on error.
 */
int wolfSSL_set1_curves_list(WOLFSSL* ssl, const char* names)
{
    WOLFSSL_ENTER("wolfSSL_set1_curves_list");
    if (ssl == NULL || names == NULL) {
        WOLFSSL_MSG("ssl or names was NULL");
        return WOLFSSL_FAILURE;
    }
    return set_curves_list(ssl, NULL, names, 1);
}

#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
#endif /* OPENSSL_EXTRA || HAVE_CURL */

#ifdef OPENSSL_EXTRA

/* Set the ALPN protocol list, in wire format, on the context.
 *
 * @param [in] ctx    SSL/TLS context object.
 * @param [in] p      ALPN protocol list in wire format (length-prefixed).
 * @param [in] p_len  Length of the protocol list in bytes.
 * @return  WOLFSSL_SUCCESS (or 0 with WOLFSSL_ERROR_CODE_OPENSSL) on success.
 * @return  BAD_FUNC_ARG when ctx or p is NULL.
 * @return  WOLFSSL_FAILURE (or 1 with WOLFSSL_ERROR_CODE_OPENSSL) on error.
 */
int wolfSSL_CTX_set_alpn_protos(WOLFSSL_CTX *ctx, const unsigned char *p,
                            unsigned int p_len)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_alpn_protos");
    if (ctx == NULL || p == NULL)
        return BAD_FUNC_ARG;
    if (ctx->alpn_cli_protos != NULL) {
        XFREE((void*)ctx->alpn_cli_protos, ctx->heap, DYNAMIC_TYPE_OPENSSL);
    }

    ctx->alpn_cli_protos = (const unsigned char*)XMALLOC(p_len,
        ctx->heap, DYNAMIC_TYPE_OPENSSL);
    if (ctx->alpn_cli_protos == NULL) {
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
        /* 0 on success in OpenSSL, non-0 on failure in OpenSSL
         * the function reverses the return value convention.
         */
        return 1;
#else
        return WOLFSSL_FAILURE;
#endif
    }
    XMEMCPY((void*)ctx->alpn_cli_protos, p, p_len);
    ctx->alpn_cli_protos_len = p_len;

#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    /* 0 on success in OpenSSL, non-0 on failure in OpenSSL
     * the function reverses the return value convention.
     */
    return 0;
#else
    return WOLFSSL_SUCCESS;
#endif
}


#ifdef HAVE_ALPN
#ifndef NO_BIO
/* Convert a wire-format ALPN protocol list into a comma-separated string.
 *
 * The wire format is a sequence of entries, each a length byte followed by
 * that many protocol-name bytes.
 *
 * @param [in]  p      ALPN protocol list in wire format.
 * @param [in]  p_len  Length of the protocol list in bytes.
 * @param [out] pt     Buffer to hold the comma-separated list. Must hold at
 *                     least p_len bytes.
 * @param [out] ptLen  Length of the comma-separated list written.
 * @return  1 on success.
 * @return  0 when the wire format is invalid.
 */
static int wolfssl_alpn_protos_to_list(const unsigned char* p,
    unsigned int p_len, char* pt, unsigned int* ptLen)
{
    unsigned int idx = 0;
    unsigned int ptIdx = 0;
    unsigned int sz;
    int ret = 1;

    /* Convert into a comma separated list. */
    while (idx < p_len - 1) {
        unsigned int i;

        sz = p[idx++];
        if (idx + sz > p_len) {
            WOLFSSL_MSG("Bad list format");
            ret = 0;
            break;
        }
        if (sz > 0) {
            for (i = 0; i < sz; i++) {
                pt[ptIdx++] = p[idx++];
            }
            if (idx < p_len - 1) {
                pt[ptIdx++] = ',';
            }
        }
    }

    if (ret == 1) {
        *ptLen = ptIdx;
    }

    return ret;
}

/* Set the ALPN protocol list, in wire format, on the object.
 *
 * The list is length-prefixed, e.g.
 *     unsigned char p[] = { 8, 'h','t','t','p','/','1','.','1' };
 *
 * @param [in] ssl    SSL/TLS object.
 * @param [in] p      ALPN protocol list in wire format (length-prefixed).
 * @param [in] p_len  Length of the protocol list in bytes.
 * @return  WOLFSSL_SUCCESS (or 0 with WOLFSSL_ERROR_CODE_OPENSSL) on success.
 * @return  WOLFSSL_FAILURE (or 1 with WOLFSSL_ERROR_CODE_OPENSSL) on error.
 */
int wolfSSL_set_alpn_protos(WOLFSSL* ssl,
        const unsigned char* p, unsigned int p_len)
{
    char* pt = NULL;
    unsigned int ptIdx = 0;
    /* RFC 7301: a server that does not select any of the client's offered
     * protocols MUST send no_application_protocol. Match that contract on
     * the OpenSSL-compat surface rather than silently continuing. */
    int alpn_opt = WOLFSSL_ALPN_FAILED_ON_MISMATCH;
#if defined(WOLFSSL_ERROR_CODE_OPENSSL)
    int ret = 1;
#else
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);
#endif

    WOLFSSL_ENTER("wolfSSL_set_alpn_protos");

    if ((ssl != NULL) && (p_len > 1) && (p != NULL)) {
        /* Replacing leading number with trailing ',' and adding '\0'. */
        pt = (char*)XMALLOC(p_len + 1, ssl->heap, DYNAMIC_TYPE_OPENSSL);
        if (pt != NULL) {
            if (wolfssl_alpn_protos_to_list(p, p_len, pt, &ptIdx)) {
                pt[ptIdx++] = '\0';

                /* Clear out all currently set ALPN extensions. */
                TLSX_Remove(&ssl->extensions, TLSX_APPLICATION_LAYER_PROTOCOL,
                    ssl->heap);

                if (wolfSSL_UseALPN(ssl, pt, ptIdx, (byte)alpn_opt) ==
                        WOLFSSL_SUCCESS) {
                #if defined(WOLFSSL_ERROR_CODE_OPENSSL)
                    ret = 0;
                #else
                    ret = WOLFSSL_SUCCESS;
                #endif
                }
            }

            XFREE(pt, ssl->heap, DYNAMIC_TYPE_OPENSSL);
        }
    }

    return ret;
}
#endif /* !NO_BIO */
#endif /* HAVE_ALPN */

#endif /* OPENSSL_EXTRA */

#endif /* !WOLFCRYPT_ONLY */

#endif /* !WOLFSSL_SSL_API_EXT_INCLUDED */
