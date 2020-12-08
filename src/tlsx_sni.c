/* tlsext_sni.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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
#include <wolfssl/tlsx_sni.h>

#ifdef HAVE_SNI

#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/******************************************************************************/
/* Server Name Indication                                                     */
/******************************************************************************/

typedef struct SNI {
    byte                       type;    /* SNI Type         */
    union { char* host_name; } data;    /* SNI Data         */
    struct SNI*                next;    /* List Behavior    */
    byte                       status;  /* Matching result  */
#ifndef NO_WOLFSSL_SERVER
    byte                       options; /* Behavior options */
#endif
} SNI;

/** Creates a new SNI object. */
static SNI* TLSX_SNI_New(byte type, const void* data, word16 size, void* heap)
{
    SNI* sni = (SNI*)XMALLOC(sizeof(SNI), heap, DYNAMIC_TYPE_TLSX);

    (void)heap;

    if (sni) {
        sni->type = type;
        sni->next = NULL;

    #ifndef NO_WOLFSSL_SERVER
        sni->options = 0;
        sni->status  = WOLFSSL_SNI_NO_MATCH;
    #endif

        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                sni->data.host_name = (char*)XMALLOC(size + 1, heap,
                                                     DYNAMIC_TYPE_TLSX);
                if (sni->data.host_name) {
                    XSTRNCPY(sni->data.host_name, (const char*)data, size);
                    sni->data.host_name[size] = '\0';
                } else {
                    XFREE(sni, heap, DYNAMIC_TYPE_TLSX);
                    sni = NULL;
                }
            break;

            default: /* invalid type */
                XFREE(sni, heap, DYNAMIC_TYPE_TLSX);
                sni = NULL;
        }
    }

    return sni;
}

/** Releases a SNI object. */
static void TLSX_SNI_Free(SNI* sni, void* heap)
{
    if (sni) {
        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                XFREE(sni->data.host_name, heap, DYNAMIC_TYPE_TLSX);
            break;
        }

        XFREE(sni, heap, DYNAMIC_TYPE_TLSX);
    }
    (void)heap;
}

/** Releases all SNI objects in the provided list. */
void TLSX_SNI_FreeAll(void* vlist, void* heap)
{
    SNI* sni;
    SNI* list = (SNI*)vlist;

    while ((sni = list)) {
        list = sni->next;
        TLSX_SNI_Free(sni, heap);
    }
}

/** Tells the buffered size of the SNI objects in a list. */
word16 TLSX_SNI_GetSize(void* vlist)
{
    SNI* sni;
    SNI* list = (SNI*)vlist;
    word16 length = OPAQUE16_LEN; /* list length */

    while ((sni = list)) {
        list = sni->next;

        length += ENUM_LEN + OPAQUE16_LEN; /* sni type + sni length */

        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                length += (word16)XSTRLEN((char*)sni->data.host_name);
            break;
        }
    }

    return length;
}

/** Writes the SNI objects of a list in a buffer. */
word16 TLSX_SNI_Write(void* vlist, byte* output)
{
    SNI* sni;
    SNI* list = (SNI*)vlist;
    word16 length = 0;
    word16 offset = OPAQUE16_LEN; /* list length offset */

    while ((sni = list)) {
        list = sni->next;

        output[offset++] = sni->type; /* sni type */

        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                length = (word16)XSTRLEN((char*)sni->data.host_name);

                c16toa(length, output + offset); /* sni length */
                offset += OPAQUE16_LEN;

                XMEMCPY(output + offset, sni->data.host_name, length);

                offset += length;
            break;
        }
    }

    c16toa(offset - OPAQUE16_LEN, output); /* writing list length */

    return offset;
}

/** Finds a SNI object in the provided list. */
static SNI* TLSX_SNI_Find(SNI *list, byte type)
{
    SNI* sni = list;

    while (sni && sni->type != type)
        sni = sni->next;

    return sni;
}

/** Sets the status of a SNI object. */
static void TLSX_SNI_SetStatus(TLSX* extensions, byte type, byte status)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_SERVER_NAME);
    SNI* sni = TLSX_SNI_Find(extension ? (SNI*)extension->data : NULL, type);

    if (sni)
        sni->status = status;
}

#ifndef NO_WOLFSSL_SERVER
/** Gets the status of a SNI object. */
static byte TLSX_SNI_Status(TLSX* extensions, byte type)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_SERVER_NAME);
    SNI* sni = TLSX_SNI_Find(extension ? (SNI*)extension->data : NULL, type);

    if (sni)
        return sni->status;

    return 0;
}
#endif

static int TLSX_UseSNI(TLSX** extensions, byte type, const void* data,
                       word16 size, void* heap);

/** Parses a buffer of SNI extensions. */
int TLSX_SNI_Parse(WOLFSSL* ssl, const byte* input, word16 length,
                   byte isRequest)
{
#ifndef NO_WOLFSSL_SERVER
    word16 size = 0;
    word16 offset = 0;
    int cacheOnly = 0;
    SNI *sni = NULL;
    byte type;
    int matchStat;
    byte matched;
#endif

    TLSX *extension = TLSX_Find(ssl->extensions, TLSX_SERVER_NAME);

    if (!extension)
        extension = TLSX_Find(ssl->ctx->extensions, TLSX_SERVER_NAME);

    if (!isRequest) {
        #ifndef NO_WOLFSSL_CLIENT
            if (!extension || !extension->data)
                return TLSX_HandleUnsupportedExtension(ssl);

            if (length > 0)
                return BUFFER_ERROR; /* SNI response MUST be empty. */

            /* This call enables wolfSSL_SNI_GetRequest() to be called in the
             * client side to fetch the used SNI. It will only work if the SNI
             * was set at the SSL object level. Right now we only support one
             * name type, WOLFSSL_SNI_HOST_NAME, but in the future, the
             * inclusion of other name types will turn this method inaccurate,
             * as the extension response doesn't contains information of which
             * name was accepted.
             */
            TLSX_SNI_SetStatus(ssl->extensions, WOLFSSL_SNI_HOST_NAME,
                                                        WOLFSSL_SNI_REAL_MATCH);

            return 0;
        #endif
    }

#ifndef NO_WOLFSSL_SERVER
    if (!extension || !extension->data) {
        /* This will keep SNI even though TLSX_UseSNI has not been called.
         * Enable it so that the received sni is available to functions
         * that use a custom callback when SNI is received.
         */
    #ifdef WOLFSSL_ALWAYS_KEEP_SNI
        cacheOnly = 1;
    #endif
        if (ssl->ctx->sniRecvCb) {
            cacheOnly = 1;
        }

        if (cacheOnly) {
            WOLFSSL_MSG("Forcing SSL object to store SNI parameter");
        }
        else {
            /* Skipping, SNI not enabled at server side. */
            return 0;
        }
    }

    if (OPAQUE16_LEN > length)
        return BUFFER_ERROR;

    ato16(input, &size);
    offset += OPAQUE16_LEN;

    /* validating sni list length */
    if (length != OPAQUE16_LEN + size || size == 0)
        return BUFFER_ERROR;

    /* SNI was badly specified and only one type is now recognized and allowed.
     * Only one SNI value per type (RFC6066), so, no loop. */
    type = input[offset++];
    if (type != WOLFSSL_SNI_HOST_NAME)
        return BUFFER_ERROR;

    if (offset + OPAQUE16_LEN > length)
        return BUFFER_ERROR;
    ato16(input + offset, &size);
    offset += OPAQUE16_LEN;

    if (offset + size != length || size == 0)
        return BUFFER_ERROR;

    if (!cacheOnly && !(sni = TLSX_SNI_Find((SNI*)extension->data, type)))
        return 0; /* not using this type of SNI. */

#ifdef WOLFSSL_TLS13
    /* Don't process the second ClientHello SNI extension if there
     * was problems with the first.
     */
    if (!cacheOnly && sni->status != 0)
        return 0;
#endif
    matched = cacheOnly || (XSTRLEN(sni->data.host_name) == size &&
         XSTRNCMP(sni->data.host_name, (const char*)input + offset, size) == 0);

    if (matched || sni->options & WOLFSSL_SNI_ANSWER_ON_MISMATCH) {
        int r = TLSX_UseSNI(&ssl->extensions, type, input + offset, size,
                                                                     ssl->heap);
        if (r != WOLFSSL_SUCCESS)
            return r; /* throws error. */

        if (cacheOnly) {
            WOLFSSL_MSG("Forcing storage of SNI, Fake match");
            matchStat = WOLFSSL_SNI_FORCE_KEEP;
        }
        else if (matched) {
            WOLFSSL_MSG("SNI did match!");
            matchStat = WOLFSSL_SNI_REAL_MATCH;
        }
        else {
            WOLFSSL_MSG("fake SNI match from ANSWER_ON_MISMATCH");
            matchStat = WOLFSSL_SNI_FAKE_MATCH;
        }

        TLSX_SNI_SetStatus(ssl->extensions, type, (byte)matchStat);

        if(!cacheOnly)
            TLSX_SetResponse(ssl, TLSX_SERVER_NAME);
    }
    else if (!(sni->options & WOLFSSL_SNI_CONTINUE_ON_MISMATCH)) {
        SendAlert(ssl, alert_fatal, unrecognized_name);

        return UNKNOWN_SNI_HOST_NAME_E;
    }
#else
    (void)input;
#endif

    return 0;
}

int TLSX_SNI_VerifyParse(WOLFSSL* ssl,  byte isRequest)
{
    (void)ssl;

    if (isRequest) {
    #ifndef NO_WOLFSSL_SERVER
        TLSX* ctx_ext = TLSX_Find(ssl->ctx->extensions, TLSX_SERVER_NAME);
        TLSX* ssl_ext = TLSX_Find(ssl->extensions,      TLSX_SERVER_NAME);
        SNI* ctx_sni = ctx_ext ? (SNI*)ctx_ext->data : NULL;
        SNI* ssl_sni = ssl_ext ? (SNI*)ssl_ext->data : NULL;
        SNI* sni = NULL;

        for (; ctx_sni; ctx_sni = ctx_sni->next) {
            if (ctx_sni->options & WOLFSSL_SNI_ABORT_ON_ABSENCE) {
                sni = TLSX_SNI_Find(ssl_sni, ctx_sni->type);

                if (sni) {
                    if (sni->status != WOLFSSL_SNI_NO_MATCH)
                        continue;

                    /* if ssl level overrides ctx level, it is ok. */
                    if ((sni->options & WOLFSSL_SNI_ABORT_ON_ABSENCE) == 0)
                        continue;
                }

                SendAlert(ssl, alert_fatal, handshake_failure);
                return SNI_ABSENT_ERROR;
            }
        }

        for (; ssl_sni; ssl_sni = ssl_sni->next) {
            if (ssl_sni->options & WOLFSSL_SNI_ABORT_ON_ABSENCE) {
                if (ssl_sni->status != WOLFSSL_SNI_NO_MATCH)
                    continue;

                SendAlert(ssl, alert_fatal, handshake_failure);
                return SNI_ABSENT_ERROR;
            }
        }
    #endif /* NO_WOLFSSL_SERVER */
    }

    return 0;
}

static int TLSX_UseSNI(TLSX** extensions, byte type, const void* data,
                       word16 size, void* heap)
{
    TLSX* extension;
    SNI* sni = NULL;

    if (extensions == NULL || data == NULL)
        return BAD_FUNC_ARG;

    if ((sni = TLSX_SNI_New(type, data, size, heap)) == NULL)
        return MEMORY_E;

    extension = TLSX_Find(*extensions, TLSX_SERVER_NAME);
    if (!extension) {
        int ret = TLSX_Push(extensions, TLSX_SERVER_NAME, (void*)sni, heap);

        if (ret != 0) {
            TLSX_SNI_Free(sni, heap);
            return ret;
        }
    }
    else {
        /* push new SNI object to extension data. */
        sni->next = (SNI*)extension->data;
        extension->data = (void*)sni;

        /* remove duplicate SNI, there should be only one of each type. */
        do {
            if (sni->next && sni->next->type == type) {
                SNI* next = sni->next;

                sni->next = next->next;
                TLSX_SNI_Free(next, heap);

                /* there is no way to occur more than
                 * two SNIs of the same type.
                 */
                break;
            }
        } while ((sni = sni->next));
    }

    return WOLFSSL_SUCCESS;
}

#ifndef NO_WOLFSSL_SERVER

/** Tells the SNI requested by the client. */
static word16 TLSX_SNI_GetRequest(TLSX* extensions, byte type, void** data)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_SERVER_NAME);
    SNI* sni = TLSX_SNI_Find(extension ? (SNI*)extension->data : NULL, type);

    if (sni && sni->status != WOLFSSL_SNI_NO_MATCH) {
        switch (sni->type) {
            case WOLFSSL_SNI_HOST_NAME:
                if (data) {
                    *data = sni->data.host_name;
                    return (word16)XSTRLEN((char*)*data);
                }
        }
    }

    return 0;
}

/** Sets the options for a SNI object. */
static void TLSX_SNI_SetOptions(TLSX* extensions, byte type, byte options)
{
    TLSX* extension = TLSX_Find(extensions, TLSX_SERVER_NAME);
    SNI* sni = TLSX_SNI_Find(extension ? (SNI*)extension->data : NULL, type);

    if (sni)
        sni->options = options;
}

/** Retrieves a SNI request from a client hello buffer. */
static int TLSX_SNI_GetFromBuffer(const byte* clientHello, word32 helloSz,
                                  byte type, byte* sni, word32* inOutSz)
{
    word32 offset = 0;
    word32 len32 = 0;
    word16 len16 = 0;

    if (helloSz < RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + CLIENT_HELLO_FIRST)
        return INCOMPLETE_DATA;

    /* TLS record header */
    if ((enum ContentType) clientHello[offset++] != handshake) {

        /* checking for SSLv2.0 client hello according to: */
        /* http://tools.ietf.org/html/rfc4346#appendix-E.1 */
        if ((enum HandShakeType) clientHello[++offset] == client_hello) {
            offset += ENUM_LEN + VERSION_SZ; /* skip version */

            ato16(clientHello + offset, &len16);
            offset += OPAQUE16_LEN;

            if (len16 % 3) /* cipher_spec_length must be multiple of 3 */
                return BUFFER_ERROR;

            ato16(clientHello + offset, &len16);
            /* Returning SNI_UNSUPPORTED do not increment offset here */

            if (len16 != 0) /* session_id_length must be 0 */
                return BUFFER_ERROR;

            return SNI_UNSUPPORTED;
        }

        return BUFFER_ERROR;
    }

    if (clientHello[offset++] != SSLv3_MAJOR)
        return BUFFER_ERROR;

    if (clientHello[offset++] < TLSv1_MINOR)
        return SNI_UNSUPPORTED;

    ato16(clientHello + offset, &len16);
    offset += OPAQUE16_LEN;

    if (offset + len16 > helloSz)
        return INCOMPLETE_DATA;

    /* Handshake header */
    if ((enum HandShakeType) clientHello[offset] != client_hello)
        return BUFFER_ERROR;

    c24to32(clientHello + offset + 1, &len32);
    offset += HANDSHAKE_HEADER_SZ;

    if (offset + len32 > helloSz)
        return BUFFER_ERROR;

    /* client hello */
    offset += VERSION_SZ + RAN_LEN; /* version, random */

    if (helloSz < offset + clientHello[offset])
        return BUFFER_ERROR;

    offset += ENUM_LEN + clientHello[offset]; /* skip session id */

    /* cypher suites */
    if (helloSz < offset + OPAQUE16_LEN)
        return BUFFER_ERROR;

    ato16(clientHello + offset, &len16);
    offset += OPAQUE16_LEN;

    if (helloSz < offset + len16)
        return BUFFER_ERROR;

    offset += len16; /* skip cypher suites */

    /* compression methods */
    if (helloSz < offset + 1)
        return BUFFER_ERROR;

    if (helloSz < offset + clientHello[offset])
        return BUFFER_ERROR;

    offset += ENUM_LEN + clientHello[offset]; /* skip compression methods */

    /* extensions */
    if (helloSz < offset + OPAQUE16_LEN)
        return 0; /* no extensions in client hello. */

    ato16(clientHello + offset, &len16);
    offset += OPAQUE16_LEN;

    if (helloSz < offset + len16)
        return BUFFER_ERROR;

    while (len16 >= OPAQUE16_LEN + OPAQUE16_LEN) {
        word16 extType;
        word16 extLen;

        ato16(clientHello + offset, &extType);
        offset += OPAQUE16_LEN;

        ato16(clientHello + offset, &extLen);
        offset += OPAQUE16_LEN;

        if (helloSz < offset + extLen)
            return BUFFER_ERROR;

        if (extType != TLSX_SERVER_NAME) {
            offset += extLen; /* skip extension */
        } else {
            word16 listLen;

            ato16(clientHello + offset, &listLen);
            offset += OPAQUE16_LEN;

            if (helloSz < offset + listLen)
                return BUFFER_ERROR;

            while (listLen > ENUM_LEN + OPAQUE16_LEN) {
                byte   sniType = clientHello[offset++];
                word16 sniLen;

                ato16(clientHello + offset, &sniLen);
                offset += OPAQUE16_LEN;

                if (helloSz < offset + sniLen)
                    return BUFFER_ERROR;

                if (sniType != type) {
                    offset  += sniLen;
                    listLen -= min(ENUM_LEN + OPAQUE16_LEN + sniLen, listLen);
                    continue;
                }

                *inOutSz = min(sniLen, *inOutSz);
                XMEMCPY(sni, clientHello + offset, *inOutSz);

                return WOLFSSL_SUCCESS;
            }
        }

        len16 -= min(2 * OPAQUE16_LEN + extLen, len16);
    }

    return len16 ? BUFFER_ERROR : 0;
}

void wolfSSL_CTX_set_servername_callback(WOLFSSL_CTX* ctx, CallbackSniRecv cb)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_servername_callback");
    if (ctx)
        ctx->sniRecvCb = cb;
}

#ifdef OPENSSL_EXTRA
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
#endif /* OPENSSL_EXTRA */

int wolfSSL_CTX_set_servername_arg(WOLFSSL_CTX* ctx, void* arg)
{
    WOLFSSL_ENTER("wolfSSL_CTX_set_servername_arg");
    if (ctx) {
        ctx->sniRecvCbArg = arg;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}

#endif /* !NO_WOLFSSL_SERVER */

#if defined(OPENSSL_ALL) || defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) \
 || defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA)

int wolfSSL_set_tlsext_host_name(WOLFSSL* ssl, const char* host_name)
{
    int ret;
    WOLFSSL_ENTER("wolfSSL_set_tlsext_host_name");
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME,
            host_name, (word16)XSTRLEN(host_name));
    WOLFSSL_LEAVE("wolfSSL_set_tlsext_host_name", ret);
    return ret;
}

#ifndef NO_WOLFSSL_SERVER
const char * wolfSSL_get_servername(WOLFSSL* ssl, byte type)
{
    void * serverName = NULL;
    if (ssl == NULL)
        return NULL;
    TLSX_SNI_GetRequest(ssl->extensions, type, &serverName);
    return (const char *)serverName;
}
#endif

#endif /* OPENSSL_ALL || HAVE_STUNNEL || WOLFSSL_NGINX || WOLFSSL_HAPROXY */

WOLFSSL_ABI
int wolfSSL_UseSNI(WOLFSSL* ssl, byte type, const void* data, word16 size)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ssl->extensions, type, data, size, ssl->heap);
}


WOLFSSL_ABI
int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, byte type, const void* data,
                                                                    word16 size)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseSNI(&ctx->extensions, type, data, size, ctx->heap);
}

#ifndef NO_WOLFSSL_SERVER

void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, byte type, byte options)
{
    if (ssl && ssl->extensions)
        TLSX_SNI_SetOptions(ssl->extensions, type, options);
}


void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx, byte type, byte options)
{
    if (ctx && ctx->extensions)
        TLSX_SNI_SetOptions(ctx->extensions, type, options);
}


byte wolfSSL_SNI_Status(WOLFSSL* ssl, byte type)
{
    return TLSX_SNI_Status(ssl ? ssl->extensions : NULL, type);
}


word16 wolfSSL_SNI_GetRequest(WOLFSSL* ssl, byte type, void** data)
{
    if (data)
        *data = NULL;

    if (ssl && ssl->extensions)
        return TLSX_SNI_GetRequest(ssl->extensions, type, data);

    return 0;
}

int wolfSSL_SNI_GetFromBuffer(const byte* clientHello, word32 helloSz,
                              byte type, byte* sni, word32* inOutSz)
{
    if (clientHello && helloSz > 0 && sni && inOutSz && *inOutSz > 0)
        return TLSX_SNI_GetFromBuffer(clientHello, helloSz, type, sni, inOutSz);

    return BAD_FUNC_ARG;
}

#endif /* NO_WOLFSSL_SERVER */

#endif /* HAVE_SNI */
