/* bio.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#if defined(OPENSSL_EXTRA) && !defined(_WIN32) && !defined(_GNU_SOURCE)
    /* turn on GNU extensions for XVASPRINTF with wolfSSL_BIO_printf */
    #define _GNU_SOURCE 1
#endif

#if !defined(WOLFSSL_BIO_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning bio.c does not need to be compiled separately from ssl.c
    #endif
#else

/*
 * WOLFSSL_BIO_RESIZE_THRESHOLD:
 *     The amount of data to return before we attempt to resize the internal
 *     buffers. After we have returned more than this define amount of bytes of
 *     data, we will resize the buffers to get rid of excess memory.
 */


/* Helper function to decode a base64 input
 *
 * returns size of resulting buffer on success
 */
static int wolfSSL_BIO_BASE64_read(WOLFSSL_BIO* bio, void* buf, int len)
{
    word32 frmtSz = (word32)len;

    WOLFSSL_ENTER("wolfSSL_BIO_BASE64_read");

    if (Base64_Decode((const byte*)buf, (word32)len, (byte*)buf, &frmtSz) !=0) {
        WOLFSSL_MSG("Err doing base64 decode");
        return WOLFSSL_FATAL_ERROR;
    }

    (void)bio;
    return (int)frmtSz;
}


/* Helper function to read from WOLFSSL_BIO_BIO type
 *
 * returns amount in bytes read on success
 */
static int wolfSSL_BIO_BIO_read(WOLFSSL_BIO* bio, void* buf, int len)
{
    int   sz1;
    int   sz2;
    char* pt;

    if (buf == NULL || len == 0)
        return 0;

    /* default no retry */
    bio->flags &= ~(WOLFSSL_BIO_FLAG_READ|WOLFSSL_BIO_FLAG_RETRY);
    sz1 = wolfSSL_BIO_nread(bio, &pt, len);
    if (sz1 > 0) {
        XMEMCPY(buf, pt, sz1);
        buf = (char*)buf + sz1;
        len -= sz1;
        if (len > 0) {
            /* try again to see if maybe we wrapped around the ring buffer */
            sz2 = wolfSSL_BIO_nread(bio, &pt, len);
            if (sz2 > 0) {
                XMEMCPY(buf, pt, sz2);
                sz1 += sz2;
            }
        }
    }
    if (sz1 == 0) {
        bio->flags |= WOLFSSL_BIO_FLAG_READ|WOLFSSL_BIO_FLAG_RETRY;
        sz1 = -1;
    }

    return sz1;
}

#ifndef WOLFSSL_BIO_RESIZE_THRESHOLD
#define WOLFSSL_BIO_RESIZE_THRESHOLD 100
#endif

/* Handles reading from a memory type BIO and advancing the state.
 *
 * bio  WOLFSSL_BIO to read from
 * buf  buffer to put data from bio in
 * len  amount of data to be read
 *
 * returns size read on success
 */
static int wolfSSL_BIO_MEMORY_read(WOLFSSL_BIO* bio, void* buf, int len)
{
    int sz;

#ifndef WOLFSSL_DEBUG_OPENSSL
    if (len > 1)
#endif
    {
    WOLFSSL_ENTER("wolfSSL_BIO_MEMORY_read");
    }

    sz = wolfSSL_BIO_pending(bio);
    if (sz > 0) {
        int memSz;

        if (bio->mem_buf == NULL) {
            WOLFSSL_MSG("bio->mem_buf is null");
            return WOLFSSL_BIO_ERROR;
        }

        if (sz > len) {
            sz = len;
        }

        memSz = (int)bio->mem_buf->length - bio->rdIdx;
        if (memSz < sz) {
            WOLFSSL_MSG("Not enough memory for reading");
            return WOLFSSL_BIO_ERROR;
        }

        XMEMCPY(buf, bio->mem_buf->data + bio->rdIdx, sz);
        bio->rdIdx += sz;

        if (bio->rdIdx >= bio->wrSz) {
            if (bio->flags & WOLFSSL_BIO_FLAG_MEM_RDONLY) {
                bio->wrSz = bio->wrSzReset;
            }
            else {
                /* All data read resize down to WOLFSSL_BIO_RESIZE_THRESHOLD */
                if (bio->mem_buf->max > WOLFSSL_BIO_RESIZE_THRESHOLD &&
                    wolfSSL_BUF_MEM_resize(bio->mem_buf, WOLFSSL_BIO_RESIZE_THRESHOLD) == 0) {
                    WOLFSSL_MSG("wolfSSL_BUF_MEM_resize error");
                    return WOLFSSL_BIO_ERROR;
                }
                bio->rdIdx = 0;
                bio->wrSz = 0;
                bio->mem_buf->length = 0;
            }
            bio->ptr.mem_buf_data = (byte *)bio->mem_buf->data;
        }
        else if (bio->rdIdx >= WOLFSSL_BIO_RESIZE_THRESHOLD &&
                !(bio->flags & WOLFSSL_BIO_FLAG_MEM_RDONLY)) {
            /* Resize the memory so we are not taking up more than necessary.
             * memmove reverts internally to memcpy if areas don't overlap */
            XMEMMOVE(bio->mem_buf->data, bio->mem_buf->data + bio->rdIdx,
                    bio->wrSz - bio->rdIdx);
            bio->wrSz -= bio->rdIdx;
            bio->rdIdx = 0;
            /* Resize down to WOLFSSL_BIO_RESIZE_THRESHOLD for fewer
             * allocations. */
            if (wolfSSL_BUF_MEM_resize(bio->mem_buf,
                    bio->wrSz > WOLFSSL_BIO_RESIZE_THRESHOLD ? bio->wrSz :
                            WOLFSSL_BIO_RESIZE_THRESHOLD) == 0) {
                WOLFSSL_MSG("wolfSSL_BUF_MEM_resize error");
                return WOLFSSL_BIO_ERROR;
            }
            bio->mem_buf->length = (size_t)bio->wrSz;
            bio->ptr.mem_buf_data = (byte *)bio->mem_buf->data;
        }
    }
    else {
        if (bio->eof < 0) /* Sanity check the eof value */
            return bio->eof;
        else {
            WOLFSSL_MSG("Weird bio->eof value. Returning default");
            return WOLFSSL_BIO_ERROR;
        }
    }

    return sz;
}

int wolfSSL_BIO_method_type(const WOLFSSL_BIO *b)
{
    return b != NULL ? b->type : (int)WOLFSSL_BIO_UNDEF;
}

#ifndef WOLFCRYPT_ONLY
#ifndef NO_TLS
/* Helper function to read from WOLFSSL_BIO_SSL type
 *
 * returns the number of bytes read on success
 */
static int wolfSSL_BIO_SSL_read(WOLFSSL_BIO* bio, void* buf,
        int len, WOLFSSL_BIO* front)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_BIO_SSL_read");

    /* already got eof, again is error */
    if ((front == NULL) || front->eof)
        return WOLFSSL_FATAL_ERROR;

    bio->flags &= ~(WOLFSSL_BIO_FLAG_RETRY); /* default no retry */
    ret = wolfSSL_read(bio->ptr.ssl, buf, len);
    if (ret == 0)
        front->eof = 1;
    else if (ret < 0) {
        int err = wolfSSL_get_error(bio->ptr.ssl, 0);
        if ( !(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) ) {
            front->eof = 1;
        }
        else {
            bio->flags |= WOLFSSL_BIO_FLAG_RETRY; /* should retry */
        }
    }

    return ret;
}
#endif /* !NO_TLS */

static int wolfSSL_BIO_MD_read(WOLFSSL_BIO* bio, void* buf, int sz)
{
    if (wolfSSL_EVP_MD_CTX_type(bio->ptr.md_ctx) == WC_NID_hmac) {
        if (wolfSSL_EVP_DigestSignUpdate(bio->ptr.md_ctx, buf,
                        (unsigned int)sz) != WOLFSSL_SUCCESS)
        {
            return WOLFSSL_FATAL_ERROR;
        }
    }
    else {
        if (wolfSSL_EVP_DigestUpdate(bio->ptr.md_ctx, buf, (size_t)sz)
                != WOLFSSL_SUCCESS) {
            return WOLFSSL_FATAL_ERROR;
        }
    }
    return sz;
}
#endif /* !WOLFCRYPT_ONLY */


/* Used to read data from a WOLFSSL_BIO structure
 *
 * bio  structure to read data from
 * buf  buffer to hold the result
 * len  length of buf buffer
 *
 * returns the number of bytes read on success
 */
int wolfSSL_BIO_read(WOLFSSL_BIO* bio, void* buf, int len)
{
    int ret = 0;
    WOLFSSL_BIO* front = bio;
    int sz  = 0;

#ifndef WOLFSSL_DEBUG_OPENSSL
    if (len > 1)
#endif
    {
    WOLFSSL_ENTER("wolfSSL_BIO_read");
    }

    /* info cb, abort if user returns <= 0*/
    if (front != NULL && front->infoCb != NULL) {
        ret = (int)front->infoCb(front, WOLFSSL_BIO_CB_READ, (const char*)buf,
                                                                     len, 0, 1);
        if (ret <= 0) {
            return ret;
        }
    }

    /* start at end of list (or a WOLFSSL_BIO_SSL object since it takes care of
     * the rest of the chain) and work backwards */
    while (bio != NULL && bio->next != NULL && bio->type != WOLFSSL_BIO_SSL) {
        bio = bio->next;
    }

    while (bio != NULL && ret >= 0) {
#ifdef WOLFSSL_BIO_HAVE_FLOW_STATS
        int inhibit_flow_increment = 0;
#endif
        /* check for custom read */
        if (bio->method && bio->method->readCb) {
            ret = bio->method->readCb(bio, (char*)buf, len);
        }
        else {
            switch (bio->type) {
            case WOLFSSL_BIO_BASE64: /* formatting data */
                if (sz > 0)
                    ret = wolfSSL_BIO_BASE64_read(bio, buf, sz);
                break;
            case WOLFSSL_BIO_BIO: /* read BIOs */
                ret = wolfSSL_BIO_BIO_read(bio, buf, len);
#ifdef WOLFSSL_BIO_HAVE_FLOW_STATS
                inhibit_flow_increment = 1;
#endif
                break;
            case WOLFSSL_BIO_MEMORY:
                ret = wolfSSL_BIO_MEMORY_read(bio, buf, len);
                break;
            case WOLFSSL_BIO_FILE:
            #ifndef NO_FILESYSTEM
                if (bio->ptr.fh) {
                    ret = (int)XFREAD(buf, 1, (size_t)len, bio->ptr.fh);
                }
                else {
                #if defined(XREAD) && !defined(NO_WOLFSSL_DIR) && \
                    !defined(WOLFSSL_NUCLEUS) && !defined(WOLFSSL_NUCLEUS_1_2)
                    ret = (int)XREAD(bio->num.fd, buf, (size_t)len);
                #else
                    WOLFSSL_MSG("No file pointer and XREAD not enabled");
                    ret = NOT_COMPILED_IN;
                #endif
                }
            #else
                WOLFSSL_MSG("WOLFSSL_BIO_FILE used with NO_FILESYSTEM");
                ret = NOT_COMPILED_IN;
            #endif /* !NO_FILESYSTEM */
                break;
            case WOLFSSL_BIO_SSL:
            #if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS)
                ret = wolfSSL_BIO_SSL_read(bio, buf, len, front);
            #else
                WOLFSSL_MSG("WOLFSSL_BIO_SSL used with WOLFCRYPT_ONLY");
                ret = NOT_COMPILED_IN;
            #endif
                break;
            case WOLFSSL_BIO_MD: /* data passing through BIO MD wrapper */
            #ifndef WOLFCRYPT_ONLY
                ret = wolfSSL_BIO_MD_read(bio, buf, ret);
            #else
                WOLFSSL_MSG("WOLFSSL_BIO_MD used with WOLFCRYPT_ONLY");
                ret = NOT_COMPILED_IN;
            #endif
                break;
            case WOLFSSL_BIO_SOCKET:
            #ifdef USE_WOLFSSL_IO
                /* BIO requires built-in socket support
                 *  (cannot be used with WOLFSSL_USER_IO) */
                bio->flags &= ~WOLFSSL_BIO_FLAG_RETRY;
                ret = wolfIO_Recv(bio->num.fd, (char*)buf, len, 0);
                if (ret == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_WANT_READ)) {
                    bio->flags |= WOLFSSL_BIO_FLAG_RETRY;
                }
                if (ret < 0) {
                    ret = WOLFSSL_BIO_ERROR;
                }
            #else
                ret = NOT_COMPILED_IN;
            #endif
                break;

            case WOLFSSL_BIO_DGRAM:
            #if defined(WOLFSSL_HAVE_BIO_ADDR) && defined(WOLFSSL_DTLS) && \
                defined(USE_WOLFSSL_IO)
                /* BIO requires built-in socket support
                 *  (cannot be used with WOLFSSL_USER_IO) */
                bio->flags &= ~WOLFSSL_BIO_FLAG_RETRY;
                if (bio->connected)
                    ret = wolfIO_Recv(bio->num.fd, (char*)buf, len, 0);
                else {
                    wolfSSL_BIO_ADDR_clear(&bio->peer_addr);
                    ret = wolfIO_RecvFrom(bio->num.fd, &bio->peer_addr,
                                          (char*)buf, len, 0);
                }
                if (ret == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_WANT_READ)) {
                    bio->flags |= WOLFSSL_BIO_FLAG_RETRY;
                }
                if (ret < 0) {
                    ret = WOLFSSL_BIO_ERROR;
                }
            #else
                ret = NOT_COMPILED_IN;
            #endif
                break;

            } /* switch */
        }

#ifdef WOLFSSL_BIO_HAVE_FLOW_STATS
        if ((ret > 0) && (!inhibit_flow_increment)) {
            bio->bytes_read += (word32)ret;
        }
#endif

        /* case where front of list is done */
        if (bio == front) {
            break; /* at front of list so be done */
        }

        if (ret > 0) {
            sz = ret; /* adjust size for formatting */
        }

        /* previous WOLFSSL_BIO in list working towards head of list */
        bio = bio->prev;
    }

    /* info cb, user can override return value */
    if (front != NULL && front->infoCb != NULL) {
        ret = (int)front->infoCb(front,
                                 WOLFSSL_BIO_CB_READ | WOLFSSL_BIO_CB_RETURN,
                                 (const char*)buf, len, 0, ret);
    }

    return ret;
}


#ifdef WOLFSSL_BASE64_ENCODE
/* Converts data into base64 output
 *
 * returns the resulting buffer size on success.
 */
/**
 * `out` buffer is allocated here and the caller is responsible
 *       for free'ing it
 * `data` and `out` can be the same in which case `data` should
 *       always be set to `out` after this function call succeeds
 */
static int wolfSSL_BIO_BASE64_write(WOLFSSL_BIO* bio, const void* data,
        word32 inLen, byte** out, word32* outLen, void* heap)
{
    byte* tmp = NULL;
    word32 sz = 0;

    WOLFSSL_ENTER("wolfSSL_BIO_BASE64_write");

    if (bio == NULL || data == NULL || out == NULL || outLen == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get the encoded length */
    if (bio->flags & WOLFSSL_BIO_FLAG_BASE64_NO_NL) {
        if (Base64_Encode_NoNl((const byte*)data, inLen, NULL,
                    &sz) != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
            WOLFSSL_MSG("Error with base64 get length");
            return WOLFSSL_FATAL_ERROR;
        }
    }
    else {
        if (Base64_Encode((const byte*)data, inLen, NULL, &sz)
              != WC_NO_ERR_TRACE(LENGTH_ONLY_E))
        {
            WOLFSSL_MSG("Error with base64 get length");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    if (sz == 0) {
        *outLen = 0;
        return 0; /* nothing to do */
    }

    /* allocate temp buffer, since base64 encode does not allow inline */
    tmp = (byte*)XMALLOC(sz, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL) {
        WOLFSSL_MSG("Memory error");
        return WOLFSSL_FATAL_ERROR;
    }
    if (bio->flags & WOLFSSL_BIO_FLAG_BASE64_NO_NL) {
        if (Base64_Encode_NoNl((const byte*)data, inLen,
                tmp, &sz) < 0) {
            WOLFSSL_MSG("Base64_Encode_NoNl error");
            XFREE(tmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFSSL_FATAL_ERROR;
        }
    }
    else {
        if (Base64_Encode((const byte*)data, inLen,
                tmp, &sz) < 0) {
            WOLFSSL_MSG("Base64_Encode error");
            XFREE(tmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFSSL_FATAL_ERROR;
        }
    }

    if (*out != NULL)
        XFREE(*out, heap, DYNAMIC_TYPE_TMP_BUFFER);
    *out = tmp;
    *outLen = sz;
    /* out is free'd by caller */

    (void)heap;

    return (int)inLen;
}
#endif /* WOLFSSL_BASE64_ENCODE */

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS)
/* Helper function for writing to a WOLFSSL_BIO_SSL type
 *
 * returns the amount written in bytes on success
 */
static int wolfSSL_BIO_SSL_write(WOLFSSL_BIO* bio, const void* data,
        int len, WOLFSSL_BIO* front)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_BIO_SSL_write");

    if (bio->ptr.ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    bio->flags &= ~(WOLFSSL_BIO_FLAG_RETRY); /* default no retry */
    ret = wolfSSL_write(bio->ptr.ssl, data, len);
    if (ret == 0)
        front->eof = 1;
    else if (ret < 0) {
        int err = wolfSSL_get_error(bio->ptr.ssl, 0);
        if ( !(err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) ) {
            front->eof = 1;
        }
        else {
            bio->flags |= WOLFSSL_BIO_FLAG_RETRY; /* should retry */
        }
    }
    return ret;
}
#endif /* !WOLFCRYPT_ONLY && !NO_TLS */

/* Writes to a WOLFSSL_BIO_BIO type.
 *
 * returns the amount written on success
 */
static int wolfSSL_BIO_BIO_write(WOLFSSL_BIO* bio, const void* data,
        int len)
{
    int   sz1;
    int   sz2;
    char* buf;

    WOLFSSL_ENTER("wolfSSL_BIO_BIO_write");

    /* adding in sanity checks for static analysis tools */
    if (bio == NULL || data == NULL || len == 0)
        return 0;

    /* default no retry */
    bio->flags &= ~(WOLFSSL_BIO_FLAG_WRITE|WOLFSSL_BIO_FLAG_RETRY);
    sz1 = wolfSSL_BIO_nwrite(bio, &buf, len);
    if (sz1 == 0) {
        bio->flags |= WOLFSSL_BIO_FLAG_WRITE|WOLFSSL_BIO_FLAG_RETRY;
        WOLFSSL_MSG("No room left to write");
        return WOLFSSL_BIO_ERROR;
    }
    if (sz1 < 0) {
        WOLFSSL_MSG("Error in wolfSSL_BIO_nwrite");
        return sz1;
    }
    XMEMCPY(buf, data, sz1);
    data = (char*)data + sz1;
    len -= sz1;

    if (len > 0) {
        /* try again to see if maybe we wrapped around the ring buffer */
        sz2 = wolfSSL_BIO_nwrite(bio, &buf, len);
        if (sz2 > 0) {
            XMEMCPY(buf, data, sz2);
            sz1 += sz2;
            if (len > sz2)
                bio->flags |= WOLFSSL_BIO_FLAG_WRITE|WOLFSSL_BIO_FLAG_RETRY;
        }
    }


    return sz1;
}


/* for complete compatibility a bio memory write allocs its own memory
 * until the application runs out ....
 *
 * bio  structure to hold incoming data
 * data buffer holding the data to be written
 * len  length of data buffer
 *
 * returns the amount of data written on success and WOLFSSL_FAILURE or
 *         WOLFSSL_BIO_ERROR for failure cases.
 */
static int wolfSSL_BIO_MEMORY_write(WOLFSSL_BIO* bio, const void* data,
        int len)
{
    WOLFSSL_ENTER("wolfSSL_BIO_MEMORY_write");

    if (bio == NULL || bio->mem_buf == NULL || data == NULL) {
        WOLFSSL_MSG("one of input parameters is null");
        return WOLFSSL_FAILURE;
    }
    if (bio->flags & WOLFSSL_BIO_FLAG_MEM_RDONLY) {
        return WOLFSSL_FAILURE;
    }

    if (len == 0)
        return WOLFSSL_SUCCESS; /* Return early to make logic simpler */

    if (wolfSSL_BUF_MEM_grow_ex(bio->mem_buf, bio->wrSz + len, 0)
            == 0) {
        WOLFSSL_MSG("Error growing memory area");
        return WOLFSSL_FAILURE;
    }

    if (bio->mem_buf->data == NULL) {
        WOLFSSL_MSG("Buffer data is NULL");
        return WOLFSSL_FAILURE;
    }

    XMEMCPY(bio->mem_buf->data + bio->wrSz, data, len);
    bio->ptr.mem_buf_data = (byte *)bio->mem_buf->data;
    bio->num.length = bio->mem_buf->max;
    bio->wrSz += len;
    bio->wrIdx += len;

    return len;
}


#ifndef WOLFCRYPT_ONLY
/* Helper function for writing to a WOLFSSL_BIO_MD type
 *
 * returns the amount written in bytes on success (0)
 */
static int wolfSSL_BIO_MD_write(WOLFSSL_BIO* bio, const void* data, int len)
{
    int ret = 0;

    if (bio == NULL || data == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wolfSSL_EVP_MD_CTX_type(bio->ptr.md_ctx) == WC_NID_hmac) {
        if (wolfSSL_EVP_DigestSignUpdate(bio->ptr.md_ctx, data,
                    (unsigned int)len) != WOLFSSL_SUCCESS) {
            ret = WOLFSSL_BIO_ERROR;
        }
    }
    else {
        if (wolfSSL_EVP_DigestUpdate(bio->ptr.md_ctx, data, (size_t)len)
                != WOLFSSL_SUCCESS) {
            ret =  WOLFSSL_BIO_ERROR;
        }
    }
    return ret;
}
#endif /* WOLFCRYPT_ONLY */


/* Writes data to a WOLFSSL_BIO structure
 *
 * bio  structure to write to
 * data holds the data to be written
 * len  length of data buffer
 *
 * returns the amount written in bytes on success
 */
int wolfSSL_BIO_write(WOLFSSL_BIO* bio, const void* data, int len)
{
    int ret = 0;
#ifdef WOLFSSL_BASE64_ENCODE
    /* Use extra return var as we want to return how much of input we have
     * written, not how big the base64 encoding ended up being */
    int retB64 = 0;
#endif
    WOLFSSL_BIO* front = bio;
    void* frmt = NULL;
    word32 frmtSz = 0;

    WOLFSSL_ENTER("wolfSSL_BIO_write");

    /* info cb, abort if user returns <= 0*/
    if (front != NULL && front->infoCb != NULL) {
        ret = (int)front->infoCb(front, WOLFSSL_BIO_CB_WRITE,
                (const char*)data, len, 0, 1);
        if (ret <= 0) {
            return ret;
        }
    }

    while (bio != NULL && ret >= 0) {
#ifdef WOLFSSL_BIO_HAVE_FLOW_STATS
        int inhibit_flow_increment = 0;
#endif
        /* check for custom write */
        if (bio->method && bio->method->writeCb) {
            ret = bio->method->writeCb(bio, (const char*)data, len);
        }
        else {
            switch (bio->type) {
            case WOLFSSL_BIO_BASE64:
            {
            #ifdef WOLFSSL_BASE64_ENCODE
                ret = retB64 = wolfSSL_BIO_BASE64_write(bio, data, (word32)len,
                                            (byte**)&frmt, &frmtSz, front->heap);
                if (ret > 0) {
                    /* change so that data is formatted buffer */
                    data = frmt;
                    len  = (int)frmtSz;
                }
            #else
                WOLFSSL_MSG("WOLFSSL_BIO_BASE64 used without "
                            "WOLFSSL_BASE64_ENCODE");
                ret = NOT_COMPILED_IN;
            #endif /* WOLFSSL_BASE64_ENCODE */
                break;
            }
            case WOLFSSL_BIO_BIO: /* write bios */
                ret = wolfSSL_BIO_BIO_write(bio, data, len);
#ifdef WOLFSSL_BIO_HAVE_FLOW_STATS
                inhibit_flow_increment = 1;
#endif
                break;
            case WOLFSSL_BIO_MEMORY:
                ret = wolfSSL_BIO_MEMORY_write(bio, data, len);
                break;
            case WOLFSSL_BIO_FILE:
            #ifndef NO_FILESYSTEM
                if (bio->ptr.fh) {
                    ret = (int)XFWRITE(data, 1, (size_t)len, bio->ptr.fh);
                }
                else {
                #if defined(XWRITE) && !defined(NO_WOLFSSL_DIR) && \
                    !defined(WOLFSSL_NUCLEUS) && !defined(WOLFSSL_NUCLEUS_1_2)
                    ret = (int)XWRITE(bio->num.fd, data, (size_t)len);
                #else
                    WOLFSSL_MSG("No file pointer and XWRITE not enabled");
                    ret = NOT_COMPILED_IN;
                #endif
                }
            #else
                WOLFSSL_MSG("WOLFSSL_BIO_FILE used with NO_FILESYSTEM");
                ret = NOT_COMPILED_IN;
            #endif /* !NO_FILESYSTEM */
                break;
            case WOLFSSL_BIO_SSL:
            #if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS)
                /* already got eof, again is error */
                if (front->eof) {
                    ret = WOLFSSL_FATAL_ERROR;
                }
                else {
                    ret = wolfSSL_BIO_SSL_write(bio, data, len, front);
                }
                /* Rest of chain is taken care of inside call */
                goto exit_chain;
            #else
                WOLFSSL_MSG("WOLFSSL_BIO_SSL used with WOLFCRYPT_ONLY");
                ret = NOT_COMPILED_IN;
            #endif
                break;
            case WOLFSSL_BIO_MD:
            #ifndef WOLFCRYPT_ONLY
                if (bio->next != NULL) { /* data passing through MD BIO */
                    ret = wolfSSL_BIO_MD_write(bio, data, len);
                }
            #else
                WOLFSSL_MSG("WOLFSSL_BIO_MD used with WOLFCRYPT_ONLY");
                ret = NOT_COMPILED_IN;
            #endif
                break;
            case WOLFSSL_BIO_SOCKET:
            #ifdef USE_WOLFSSL_IO
                /* BIO requires built-in socket support
                 *  (cannot be used with WOLFSSL_USER_IO) */
                bio->flags &= ~WOLFSSL_BIO_FLAG_RETRY;
                ret = wolfIO_Send(bio->num.fd, (char*)data, len, 0);
                if (ret == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_WANT_WRITE)) {
                    bio->flags |= WOLFSSL_BIO_FLAG_RETRY;
                }
                if (ret < 0) {
                    ret = WOLFSSL_BIO_ERROR;
                }
            #else
                ret = NOT_COMPILED_IN;
            #endif
                break;

            case WOLFSSL_BIO_DGRAM:
                #if defined(WOLFSSL_HAVE_BIO_ADDR) && defined(WOLFSSL_DTLS) && \
                    defined(USE_WOLFSSL_IO)
                /* BIO requires built-in socket support
                 *  (cannot be used with WOLFSSL_USER_IO) */
                bio->flags &= ~WOLFSSL_BIO_FLAG_RETRY;
                if (bio->connected)
                    ret = wolfIO_Send(bio->num.fd, (char*)data, len, 0);
                else if (bio->peer_addr.sa.sa_family == AF_UNSPEC)
                    ret = SOCKET_ERROR_E;
                else
                    ret = wolfIO_SendTo(bio->num.fd, &bio->peer_addr, (char*)data, len, 0);
                if (ret == WC_NO_ERR_TRACE(WOLFSSL_CBIO_ERR_WANT_WRITE)) {
                    bio->flags |= WOLFSSL_BIO_FLAG_RETRY;
                }
                if (ret < 0) {
                    ret = WOLFSSL_BIO_ERROR;
                }
            #else
                ret = NOT_COMPILED_IN;
            #endif
                break;

            } /* switch */
        }

#ifdef WOLFSSL_BIO_HAVE_FLOW_STATS
        if ((ret > 0) && (! inhibit_flow_increment))
            bio->bytes_written += (word32)ret;
#endif

        /* advance to the next bio in list */
        bio = bio->next;
    }

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS)
exit_chain:
#endif

    /* info cb, user can override return value */
    if (front != NULL && front->infoCb != NULL) {
        ret = (int)front->infoCb(front,
                                 WOLFSSL_BIO_CB_WRITE | WOLFSSL_BIO_CB_RETURN,
                                 (const char*)data, len, 0, ret);
    }

    if (front != NULL) {
        XFREE(frmt, front->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

#ifdef WOLFSSL_BASE64_ENCODE
    if (retB64 > 0 && ret > 0)
        return retB64;
    else
#endif
        return ret;
}


/* Wrapper for other BIO type functions, expected to grow as OpenSSL compatibility
 * layer grows.
 *
 * return info. specific to the cmd that is passed in.
 */
#if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
long wolfSSL_BIO_ctrl(WOLFSSL_BIO *bio, int cmd, long larg, void *parg)
{
    long ret;

    (void)larg; /* not currently used */

    WOLFSSL_ENTER("wolfSSL_BIO_ctrl");

    if (bio && bio->method && bio->method->ctrlCb) {
        return bio->method->ctrlCb(bio, cmd, larg, parg);
    }

    switch(cmd) {
        case WOLFSSL_BIO_CTRL_PENDING:
        case WOLFSSL_BIO_CTRL_WPENDING:
            ret = (long)wolfSSL_BIO_ctrl_pending(bio);
            break;
        case WOLFSSL_BIO_CTRL_INFO:
            ret = (long)wolfSSL_BIO_get_mem_data(bio, parg);
            break;
        case WOLFSSL_BIO_CTRL_FLUSH:
            ret = (long)wolfSSL_BIO_flush(bio);
            break;
        case WOLFSSL_BIO_CTRL_RESET:
            ret = (long)wolfSSL_BIO_reset(bio);
            break;

#ifdef WOLFSSL_HAVE_BIO_ADDR
        case WOLFSSL_BIO_CTRL_DGRAM_CONNECT:
        case WOLFSSL_BIO_CTRL_DGRAM_SET_PEER:
        {
            socklen_t addr_size;
            if (parg == NULL) {
                ret = WOLFSSL_FAILURE;
                break;
            }
            addr_size = wolfSSL_BIO_ADDR_size((WOLFSSL_BIO_ADDR *)parg);
            if (addr_size == 0) {
                ret = WOLFSSL_FAILURE;
                break;
            }
            XMEMCPY(&bio->peer_addr, parg, addr_size);
            ret = WOLFSSL_SUCCESS;
            break;
        }

        case WOLFSSL_BIO_CTRL_DGRAM_SET_CONNECTED:
            if (parg == NULL) {
                wolfSSL_BIO_ADDR_clear(&bio->peer_addr);
                bio->connected = 0;
            }
            else {
                socklen_t addr_size = wolfSSL_BIO_ADDR_size((WOLFSSL_BIO_ADDR *)parg);
                if (addr_size == 0) {
                    ret = WOLFSSL_FAILURE;
                    break;
                }
                XMEMCPY(&bio->peer_addr, parg, addr_size);
                bio->connected = 1;
            }
            ret = WOLFSSL_SUCCESS;
            break;

        case WOLFSSL_BIO_CTRL_DGRAM_QUERY_MTU:
            ret = 0; /* not implemented */
            break;

#endif /* WOLFSSL_HAVE_BIO_ADDR */

        default:
            WOLFSSL_MSG("CMD not yet implemented");
            ret = WOLFSSL_FAILURE;
            break;
    }
    return ret;
}

/* Increment the WOLFSSL_BIO ref count by one, prevents BIO from being
 * freed until ref count is back down to 1.
 *
 * bio  the structure to increment ref count
 *
 * returns 1 on success, 0 on failure */

int wolfSSL_BIO_up_ref(WOLFSSL_BIO* bio)
{
    if (bio) {
        int ret;
        wolfSSL_RefInc(&bio->ref, &ret);
    #ifdef WOLFSSL_REFCNT_ERROR_RETURN
        if (ret != 0) {
            WOLFSSL_MSG("Failed to lock BIO mutex");
        }
    #else
        (void)ret;
    #endif

        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}

#ifdef WOLFSSL_HAVE_BIO_ADDR
WOLFSSL_BIO_ADDR *wolfSSL_BIO_ADDR_new(void) {
    WOLFSSL_BIO_ADDR *addr =
        (WOLFSSL_BIO_ADDR *)XMALLOC(sizeof(*addr), NULL, DYNAMIC_TYPE_BIO);
    if (addr)
        addr->sa.sa_family = AF_UNSPEC;
    return addr;
}

void wolfSSL_BIO_ADDR_free(WOLFSSL_BIO_ADDR *addr) {
    XFREE(addr, NULL, DYNAMIC_TYPE_BIO);
}

void wolfSSL_BIO_ADDR_clear(WOLFSSL_BIO_ADDR *addr) {
    if (addr == NULL)
        return;
    XMEMSET(addr, 0, sizeof(*addr));
    addr->sa.sa_family = AF_UNSPEC;
}

socklen_t wolfSSL_BIO_ADDR_size(const WOLFSSL_BIO_ADDR *addr) {
    switch (addr->sa.sa_family) {
#ifndef WOLFSSL_NO_BIO_ADDR_IN
    case AF_INET:
        return sizeof(addr->sa_in);
#endif
#ifdef WOLFSSL_IPV6
    case AF_INET6:
        return sizeof(addr->sa_in6);
#endif
#if defined(HAVE_SYS_UN_H) && !defined(WOLFSSL_NO_SOCKADDR_UN)
    case AF_UNIX:
        return sizeof(addr->sa_un);
#endif
    default:
        /* must return zero if length can't be determined, to avoid buffer
         * overruns in callers.
         */
        return 0;
    }
}
#endif /* WOLFSSL_HAVE_BIO_ADDR */

#endif /* OPENSSL_ALL || OPENSSL_EXTRA */

/* helper function for wolfSSL_BIO_gets
 * size till a newline is hit
 * returns the number of bytes including the new line character
 */
static int wolfSSL_getLineLength(char* in, int inSz)
{
    int i;

    for (i = 0; i < inSz; i++) {
        if (in[i] == '\n') {
            return i + 1; /* includes new line character */
        }
    }

    return inSz; /* rest of buffer is all one line */
}


/* Gets the next line from bio. Goes until a new line character or end of
 * buffer is reached.
 *
 * bio  the structure to read a new line from
 * buf  buffer to hold the result
 * sz   the size of "buf" buffer
 *
 * returns the size of the result placed in buf on success and a 0 or negative
 *         value in an error case.
 */
int wolfSSL_BIO_gets(WOLFSSL_BIO* bio, char* buf, int sz)
{
    int ret = WOLFSSL_BIO_UNSET;

    WOLFSSL_ENTER("wolfSSL_BIO_gets");

    if (bio == NULL || buf == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* not enough space for character plus terminator */
    if (sz <= 1) {
        return 0;
    }

    /* info cb, abort if user returns <= 0*/
    if (bio->infoCb != NULL) {
        ret = (int)bio->infoCb(bio, WOLFSSL_BIO_CB_GETS, buf, sz, 0, 1);
        if (ret <= 0) {
            return ret;
        }
    }

    /* check if is custom method */
    if (bio->method && bio->method->getsCb) {
        return bio->method->getsCb(bio, buf, sz);
    }

    switch (bio->type) {
#ifndef NO_FILESYSTEM
        case WOLFSSL_BIO_FILE:
            if (bio->ptr.fh == XBADFILE) {
                return WOLFSSL_BIO_ERROR;
            }

            #if defined(MICRIUM) || defined(LSR_FS) || defined(EBSNET)
            WOLFSSL_MSG("XFGETS not ported for this system yet");
            ret = XFGETS(buf, sz, bio->ptr.fh);
            #else
            if (XFGETS(buf, sz, bio->ptr.fh) != NULL) {
                ret = (int)XSTRLEN(buf);
            }
            else {
                ret = WOLFSSL_BIO_ERROR;
            }
            #endif
            break;
#endif /* NO_FILESYSTEM */
        case WOLFSSL_BIO_MEMORY:
            {
                const byte* c;
                int   cSz;
                cSz = wolfSSL_BIO_pending(bio);
                if (cSz == 0) {
                    ret = 0; /* Nothing to read */
                    buf[0] = '\0';
                    break;
                }

                if (wolfSSL_BIO_get_mem_data(bio, (void*)&c) <= 0) {
                    ret = WOLFSSL_BIO_ERROR;
                    break;
                }

                cSz = wolfSSL_getLineLength((char*)c, cSz);
                /* check case where line was bigger then buffer and buffer
                 * needs end terminator */
                if (cSz >= sz) {
                    cSz = sz - 1;
                    buf[cSz] = '\0';
                }
                else {
                    /* not minus 1 here because placing terminator after
                       msg and have checked that sz is large enough */
                    buf[cSz] = '\0';
                }

                ret = wolfSSL_BIO_MEMORY_read(bio, (void*)buf, cSz);
                /* ret is read after the switch statement */
                break;
            }
        case WOLFSSL_BIO_BIO:
            {
                char* c;
                int   cSz;
                cSz = wolfSSL_BIO_nread0(bio, &c);
                if (cSz <= 0) {
                    ret = 0; /* Nothing to read */
                    buf[0] = '\0';
                    break;
                }

                cSz = wolfSSL_getLineLength(c, cSz);
                /* check case where line was bigger then buffer and buffer
                 * needs end terminator */
                if (cSz >= sz) {
                    cSz = sz - 1;
                    buf[cSz] = '\0';
                }
                else {
                    /* not minus 1 here because placing terminator after
                       msg and have checked that sz is large enough */
                    buf[cSz] = '\0';
                }

                ret = wolfSSL_BIO_nread(bio, &c, cSz);
                if (ret > 0 && ret < sz) {
                    XMEMCPY(buf, c, ret);
                }
                break;
            }

#ifndef WOLFCRYPT_ONLY
        /* call final on hash */
        case WOLFSSL_BIO_MD:
            if (wolfSSL_EVP_MD_CTX_size(bio->ptr.md_ctx) > sz) {
                WOLFSSL_MSG("Output buffer was too small for digest");
                ret = WOLFSSL_FAILURE;
            }
            else {
                unsigned int szOut = 0;
                ret = wolfSSL_EVP_DigestFinal(bio->ptr.md_ctx,
                        (unsigned char*)buf, &szOut);
                if (ret == WOLFSSL_SUCCESS) {
                    ret = (int)szOut;
                }
            }
            break;
#endif /* WOLFCRYPT_ONLY */

        default:
            WOLFSSL_MSG("BIO type not supported yet with wolfSSL_BIO_gets");
    }

    /* info cb, user can override return value */
    if (bio->infoCb != NULL) {
        ret = (int)bio->infoCb(bio, WOLFSSL_BIO_CB_GETS | WOLFSSL_BIO_CB_RETURN,
                               buf, sz, 0, ret);
    }

    return ret;
}


/* Writes a null terminated string to bio.
 *
 * bio  the structure to write to
 * buf  buffer to holding input string
 *
 * returns the size of the result placed in bio on success and a 0 or negative
 *         value in an error case. -2 is returned if the implementation is not
 *         supported for the BIO type.
 */
int wolfSSL_BIO_puts(WOLFSSL_BIO* bio, const char* buf)
{
    int sz;

    if (bio == NULL || buf == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    /* check if is custom method */
    if (bio->method && bio->method->putsCb) {
        return bio->method->putsCb(bio, buf);
    }

    sz = (int)XSTRLEN(buf);
    if (sz <= 0) {
        return WOLFSSL_FATAL_ERROR;
    }

    return wolfSSL_BIO_write(bio, buf, sz);
}


/* searches through bio list for a BIO of type "type"
 * returns NULL on failure to find a given type */
WOLFSSL_BIO* wolfSSL_BIO_find_type(WOLFSSL_BIO* bio, int type)
{
    WOLFSSL_BIO* local = NULL;
    WOLFSSL_BIO* current;

    WOLFSSL_ENTER("wolfSSL_BIO_find_type");

    if (bio == NULL) {
        return local;
    }

    current = bio;
    while (current != NULL) {
        if (current->type == type) {
            WOLFSSL_MSG("Found matching WOLFSSL_BIO type");
            local = current;
            break;
        }
        current = current->next;
    }

    return local;
}


/* returns a pointer to the next WOLFSSL_BIO in the chain on success.
 * If a failure case then NULL is returned */
WOLFSSL_BIO* wolfSSL_BIO_next(WOLFSSL_BIO* bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_next");

    if (bio == NULL) {
        WOLFSSL_MSG("Bad argument passed in");
        return NULL;
    }

    return bio->next;
}

/* BIO_wpending returns the number of bytes pending to be written. */
size_t wolfSSL_BIO_wpending(const WOLFSSL_BIO *bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_wpending");

    if (bio == NULL)
        return 0;

    if (bio->type == WOLFSSL_BIO_MEMORY) {
        return bio->wrSz;
    }

    /* type BIO_BIO then check paired buffer */
    if (bio->type == WOLFSSL_BIO_BIO && bio->pair != NULL) {
        WOLFSSL_BIO* pair = bio->pair;
        return pair->wrIdx;
    }

    return 0;
}

/* Custom wolfSSL API to check if current bio object supports checking
 * pending state.
 */
int wolfSSL_BIO_supports_pending(const WOLFSSL_BIO *bio)
{
    while (bio) {
        if (bio->type == WOLFSSL_BIO_SSL ||
                bio->type == WOLFSSL_BIO_MEMORY ||
                bio->type == WOLFSSL_BIO_BIO)
            return 1;
        bio = bio->next;
    }
    return 0;
}

/* Return the number of pending bytes in read and write buffers */
size_t wolfSSL_BIO_ctrl_pending(WOLFSSL_BIO *bio)
{
#ifdef WOLFSSL_DEBUG_OPENSSL
    WOLFSSL_ENTER("wolfSSL_BIO_ctrl_pending");
#endif

    if (bio == NULL) {
        return 0;
    }

    if (bio->type == WOLFSSL_BIO_MD ||
            bio->type == WOLFSSL_BIO_BASE64) {
        /* these are wrappers only, get next bio */
        while (bio->next != NULL) {
            bio = bio->next;
            if (bio->type == WOLFSSL_BIO_MD ||
                    bio->type == WOLFSSL_BIO_BASE64) {
                break;
            }
        }
    }

#ifndef WOLFCRYPT_ONLY
    if (bio->type == WOLFSSL_BIO_SSL && bio->ptr.ssl != NULL) {
        return (long)wolfSSL_pending(bio->ptr.ssl);
    }
#endif

    if (bio->type == WOLFSSL_BIO_MEMORY) {
        return bio->wrSz - bio->rdIdx;
    }

    /* type BIO_BIO then check paired buffer */
    if (bio->type == WOLFSSL_BIO_BIO && bio->pair != NULL) {
        WOLFSSL_BIO* pair = bio->pair;
        if (pair->wrIdx > 0 && pair->wrIdx <= pair->rdIdx) {
            /* in wrap around state where beginning of buffer is being
             * overwritten */
            return pair->wrSz - pair->rdIdx + pair->wrIdx;
        }
        else {
            /* simple case where has not wrapped around */
            return pair->wrIdx - pair->rdIdx;
        }
    }
    return 0;
}


long wolfSSL_BIO_get_mem_ptr(WOLFSSL_BIO *bio, WOLFSSL_BUF_MEM **ptr)
{
    WOLFSSL_BIO* front = bio;
    long ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);

    WOLFSSL_ENTER("wolfSSL_BIO_get_mem_ptr");

    if (bio == NULL || ptr == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* start at end and work backwards to find a memory BIO in the BIO chain */
    while ((bio != NULL) && (bio->next != NULL)) {
        bio = bio->next;
    }

    while (bio != NULL) {

        if (bio->type == WOLFSSL_BIO_MEMORY) {
            *ptr = bio->mem_buf;
            ret = WOLFSSL_SUCCESS;
        }

        if (bio == front) {
            break;
        }
        bio = bio->prev;
    }

    if (ret == WOLFSSL_SUCCESS)
        return ret;
    else
        return WOLFSSL_FAILURE;
}

#ifdef OPENSSL_ALL
    int wolfSSL_BIO_set_mem_buf(WOLFSSL_BIO* bio, WOLFSSL_BUF_MEM* bufMem,
                                int closeFlag)
    {
        if (!bio || !bufMem ||
           (closeFlag != WOLFSSL_BIO_NOCLOSE && closeFlag != WOLFSSL_BIO_CLOSE))
            return BAD_FUNC_ARG;

        if (bio->mem_buf)
            if (closeFlag == BIO_CLOSE)
                wolfSSL_BUF_MEM_free(bio->mem_buf);

        bio->mem_buf = bufMem;
        bio->shutdown = closeFlag ? WOLFSSL_BIO_CLOSE : WOLFSSL_BIO_NOCLOSE;

        bio->wrSz = (int)bio->mem_buf->length;
        bio->wrSzReset = bio->wrSz;
        bio->num.length = bio->mem_buf->max;
        bio->ptr.mem_buf_data = (byte *)bio->mem_buf->data;
        bio->wrIdx = 0;
        bio->rdIdx = 0;

        return WOLFSSL_SUCCESS;
    }
#endif

WOLFSSL_API long wolfSSL_BIO_int_ctrl(WOLFSSL_BIO *bp, int cmd, long larg, int iarg)
{
    (void) bp;
    (void) cmd;
    (void) larg;
    (void) iarg;
    WOLFSSL_STUB("BIO_int_ctrl");
    return 0;
}


int wolfSSL_BIO_set_write_buf_size(WOLFSSL_BIO *bio, long size)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_write_buf_size");

    if (bio == NULL || bio->type != WOLFSSL_BIO_BIO || (int)size < 0) {
        return WOLFSSL_FAILURE;
    }

    /* if already in pair then do not change size */
    if (bio->pair != NULL) {
        WOLFSSL_MSG("WOLFSSL_BIO is paired, free from pair before changing");
        return WOLFSSL_FAILURE;
    }

    if (bio->ptr.mem_buf_data != NULL) {
        XFREE(bio->ptr.mem_buf_data, bio->heap, DYNAMIC_TYPE_OPENSSL);
    }

    bio->ptr.mem_buf_data = (byte*)XMALLOC(size, bio->heap,
                                           DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr.mem_buf_data == NULL) {
        WOLFSSL_MSG("Memory allocation error");
        bio->wrSz  = 0;
        bio->num.length = 0;
        bio->wrIdx = 0;
        bio->rdIdx = 0;
        if (bio->mem_buf != NULL) {
            bio->mem_buf->data = NULL;
            bio->mem_buf->length = 0;
            bio->mem_buf->max = 0;
        }
        return WOLFSSL_FAILURE;
    }
    bio->wrSz  = (int)size;
    bio->num.length = size;
    bio->wrIdx = 0;
    bio->rdIdx = 0;
    if (bio->mem_buf != NULL) {
        bio->mem_buf->data = (char*)bio->ptr.mem_buf_data;
        bio->mem_buf->length = bio->num.length;
        bio->mem_buf->max = bio->num.length;
    }

    return WOLFSSL_SUCCESS;
}


/* Joins two BIO_BIO types. The write of b1 goes to the read of b2 and vice
 * versa. Creating something similar to a two way pipe.
 * Reading and writing between the two BIOs is not thread safe, they are
 * expected to be used by the same thread. */
int wolfSSL_BIO_make_bio_pair(WOLFSSL_BIO *b1, WOLFSSL_BIO *b2)
{
    WOLFSSL_ENTER("wolfSSL_BIO_make_bio_pair");

    if (b1 == NULL || b2 == NULL) {
        WOLFSSL_LEAVE("wolfSSL_BIO_make_bio_pair", BAD_FUNC_ARG);
        return WOLFSSL_FAILURE;
    }

    /* both are expected to be of type BIO and not already paired */
    if (b1->type != WOLFSSL_BIO_BIO || b2->type != WOLFSSL_BIO_BIO ||
        b1->pair != NULL || b2->pair != NULL) {
        WOLFSSL_MSG("Expected type BIO and not already paired");
        return WOLFSSL_FAILURE;
    }

    /* set default write size if not already set */
    if (b1->ptr.mem_buf_data == NULL && wolfSSL_BIO_set_write_buf_size(b1,
                            WOLFSSL_BIO_SIZE) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    if (b2->ptr.mem_buf_data == NULL && wolfSSL_BIO_set_write_buf_size(b2,
                            WOLFSSL_BIO_SIZE) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    b1->pair = b2;
    b2->pair = b1;

    return WOLFSSL_SUCCESS;
}


int wolfSSL_BIO_ctrl_reset_read_request(WOLFSSL_BIO *b)
{
    WOLFSSL_ENTER("wolfSSL_BIO_ctrl_reset_read_request");

    if (b == NULL || b->type == WOLFSSL_BIO_MEMORY) {
        return WOLFSSL_FAILURE;
    }

    b->readRq = 0;

    return WOLFSSL_SUCCESS;
}


/* Does not advance read index pointer */
int wolfSSL_BIO_nread0(WOLFSSL_BIO *bio, char **buf)
{
    WOLFSSL_ENTER("wolfSSL_BIO_nread0");

    if (bio == NULL || buf == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        return -2;
    }

    /* if paired read from pair */
    if (bio->pair != NULL) {
        WOLFSSL_BIO* pair = bio->pair;

        /* case where have wrapped around write buffer */
        *buf = (char*)pair->ptr.mem_buf_data + pair->rdIdx;
        if (pair->wrIdx > 0 && pair->rdIdx >= pair->wrIdx) {
            return pair->wrSz - pair->rdIdx;
        }
        else {
            return pair->wrIdx - pair->rdIdx;
        }
    }

    return -2;
}


/* similar to wolfSSL_BIO_nread0 but advances the read index */
int wolfSSL_BIO_nread(WOLFSSL_BIO *bio, char **buf, int num)
{
    int sz = WOLFSSL_BIO_UNSET;

    WOLFSSL_ENTER("wolfSSL_BIO_nread");

    if (bio == NULL || buf == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        return WOLFSSL_FAILURE;
    }

    if (bio->type == WOLFSSL_BIO_MEMORY) {
        return WOLFSSL_FAILURE;
    }

    if (bio->pair != NULL) {
        /* special case if asking to read 0 bytes */
        if (num == 0) {
            *buf = (char*)bio->pair->ptr.mem_buf_data + bio->pair->rdIdx;
            return 0;
        }

        /* get amount able to read and set buffer pointer */
        sz = wolfSSL_BIO_nread0(bio, buf);
        if (sz < 0) {
            return WOLFSSL_BIO_ERROR;
        }

        if (num < sz) {
            sz = num;
        }
        bio->pair->rdIdx += sz;
#ifdef WOLFSSL_BIO_HAVE_FLOW_STATS
        bio->pair->bytes_read += (word32)sz;
#endif

        /* check if have read to the end of the buffer and need to reset */
        if (bio->pair->rdIdx == bio->pair->wrSz) {
            bio->pair->rdIdx = 0;
            if (bio->pair->wrIdx == bio->pair->wrSz) {
                bio->pair->wrIdx = 0;
            }
        }

        /* check if read up to write index, if so then reset index */
        if (bio->pair->rdIdx == bio->pair->wrIdx) {
            bio->pair->rdIdx = 0;
            bio->pair->wrIdx = 0;
        }
    }

    return sz;
}


int wolfSSL_BIO_nwrite(WOLFSSL_BIO *bio, char **buf, int num)
{
    int sz = WOLFSSL_BIO_UNSET;

    WOLFSSL_ENTER("wolfSSL_BIO_nwrite");

    if (bio == NULL || buf == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        return 0;
    }

    if (bio->type != WOLFSSL_BIO_BIO) {
        return WOLFSSL_FAILURE;
    }

    if (bio->pair != NULL) {
        if (num == 0) {
            *buf = (char*)bio->ptr.mem_buf_data + bio->wrIdx;
            return 0;
        }

        if (bio->wrIdx < bio->rdIdx) {
            /* if wrapped around only write up to read index. In this case
             * rdIdx is always greater then wrIdx so sz will not be negative. */
            sz = bio->rdIdx - bio->wrIdx;
        }
        else if (bio->rdIdx > 0 && bio->wrIdx == bio->rdIdx) {
            return WOLFSSL_BIO_ERROR; /* no more room to write */
        }
        else {
            /* write index is past read index so write to end of buffer */
            sz = bio->wrSz - bio->wrIdx;

            if (sz <= 0) {
                /* either an error has occurred with write index or it is at the
                 * end of the write buffer. */
                if (bio->rdIdx == 0) {
                    /* no more room, nothing has been read */
                    return WOLFSSL_BIO_ERROR;
                }

                bio->wrIdx = 0;

                /* check case where read index is not at 0 */
                if (bio->rdIdx > 0) {
                    sz = bio->rdIdx; /* can write up to the read index */
                }
                else {
                    sz = bio->wrSz; /* no restriction other then buffer size */
                }
            }
        }

        if (num < sz) {
            sz = num;
        }
        *buf = (char*)bio->ptr.mem_buf_data + bio->wrIdx;
        bio->wrIdx += sz;
#ifdef WOLFSSL_BIO_HAVE_FLOW_STATS
        bio->bytes_written += (word32)sz;
#endif

        /* if at the end of the buffer and space for wrap around then set
         * write index back to 0 */
        if (bio->wrIdx == bio->wrSz && bio->rdIdx > 0) {
            bio->wrIdx = 0;
        }
    }

    return sz;
}

#ifdef WOLFSSL_BIO_HAVE_FLOW_STATS
word64 wolfSSL_BIO_number_read(WOLFSSL_BIO *bio)
{
    word64 ret = 0;
    if (bio == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        return 0;
    }
    while (bio) {
        ret += bio->bytes_read;
        bio = bio->next;
    }

    return ret;
}

word64 wolfSSL_BIO_number_written(WOLFSSL_BIO *bio)
{
    word64 ret = 0;
    if (bio == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        return 0;
    }
    while (bio) {
        ret += bio->bytes_written;
        bio = bio->next;
    }

    return ret;
}
#endif /* WOLFSSL_BIO_HAVE_FLOW_STATS */

/* Reset BIO to initial state */
int wolfSSL_BIO_reset(WOLFSSL_BIO *bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_reset");

    if (bio == NULL) {
        WOLFSSL_MSG("NULL argument passed in");
        /* -1 is consistent failure even for FILE type */
        return WOLFSSL_BIO_ERROR;
    }

    switch (bio->type) {
        #ifndef NO_FILESYSTEM
        case WOLFSSL_BIO_FILE:
            if (XFSEEK(bio->ptr.fh, 0, XSEEK_SET) != 0)
                return WOLFSSL_BIO_ERROR;
            else
                return WOLFSSL_SUCCESS;
        #endif

        case WOLFSSL_BIO_BIO:
            bio->rdIdx = 0;
            bio->wrIdx = 0;
            return WOLFSSL_SUCCESS;

        case WOLFSSL_BIO_MEMORY:
            bio->rdIdx = 0;
            if (bio->flags & WOLFSSL_BIO_FLAG_MEM_RDONLY) {
                bio->wrIdx = bio->wrSzReset;
                bio->wrSz  = bio->wrSzReset;
            }
            else {
                bio->wrSz  = 0;
                XFREE(bio->ptr.mem_buf_data, bio->heap, DYNAMIC_TYPE_OPENSSL);
                bio->ptr.mem_buf_data = NULL;
                bio->num.length = 0;
                if (bio->mem_buf != NULL) {
                    bio->mem_buf->data = NULL;
                    bio->mem_buf->length = 0;
                    bio->mem_buf->max = 0;
                }
            }
            return WOLFSSL_SUCCESS;

#ifndef WOLFCRYPT_ONLY
        case WOLFSSL_BIO_MD:
            if (bio->ptr.md_ctx != NULL) {
                const WOLFSSL_EVP_MD* md =
                    wolfSSL_EVP_MD_CTX_md(bio->ptr.md_ctx);
                wolfSSL_EVP_MD_CTX_cleanup(bio->ptr.md_ctx);
                wolfSSL_EVP_MD_CTX_init(bio->ptr.md_ctx);
                wolfSSL_EVP_DigestInit(bio->ptr.md_ctx, md);
            }
            return WOLFSSL_SUCCESS;
#endif /* WOLFCRYPT_ONLY */

        default:
            WOLFSSL_MSG("Unknown BIO type needs added to reset function");
    }

    return WOLFSSL_BIO_ERROR;
}

#ifndef NO_FILESYSTEM
/**
 * Creates a new file BIO object
 * @param fd file descriptor for to use for the new object
 * @param close_flag BIO_NOCLOSE or BIO_CLOSE
 * @return New BIO object or NULL on failure
 */
WOLFSSL_BIO *wolfSSL_BIO_new_fd(int fd, int close_flag)
{
    WOLFSSL_BIO* bio;

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    if (!bio) {
        WOLFSSL_MSG("wolfSSL_BIO_new error");
        return NULL;
    }

    if (wolfSSL_BIO_set_fd(bio, fd, close_flag) != WOLFSSL_SUCCESS) {
        wolfSSL_BIO_free(bio);
        WOLFSSL_MSG("wolfSSL_BIO_set_fp error");
        return NULL;
    }

    return bio;
}

long wolfSSL_BIO_set_fp(WOLFSSL_BIO *bio, XFILE fp, int c)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_fp");

    if (bio == NULL || fp == XBADFILE) {
        WOLFSSL_LEAVE("wolfSSL_BIO_set_fp", BAD_FUNC_ARG);
        return WOLFSSL_FAILURE;
    }

    if (bio->type != WOLFSSL_BIO_FILE) {
        return WOLFSSL_FAILURE;
    }

    bio->shutdown = (byte)c;
    bio->ptr.fh = fp;

    return WOLFSSL_SUCCESS;
}


long wolfSSL_BIO_get_fp(WOLFSSL_BIO *bio, XFILE* fp)
{
    WOLFSSL_ENTER("wolfSSL_BIO_get_fp");

    if (bio == NULL || fp == XBADFILE) {
        return WOLFSSL_FAILURE;
    }

    if (bio->type != WOLFSSL_BIO_FILE) {
        return WOLFSSL_FAILURE;
    }

    *fp = bio->ptr.fh;

    return WOLFSSL_SUCCESS;
}

/* overwrites file */
int wolfSSL_BIO_write_filename(WOLFSSL_BIO *bio, char *name)
{
    WOLFSSL_ENTER("wolfSSL_BIO_write_filename");

    if (bio == NULL || name == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (bio->type == WOLFSSL_BIO_FILE) {
        if (bio->ptr.fh != XBADFILE && bio->shutdown == WOLFSSL_BIO_CLOSE) {
            XFCLOSE(bio->ptr.fh);
        }

        /* 'b' flag is ignored on POSIX targets, but on Windows it assures
         * inhibition of LF<->CRLF rewriting, so that there is consistency
         * between the size and contents of the representation in memory and on
         * disk.
         */
        bio->ptr.fh = XFOPEN(name, "wb");
        if (bio->ptr.fh == XBADFILE) {
            return WOLFSSL_FAILURE;
        }
        bio->shutdown = WOLFSSL_BIO_CLOSE;

        return WOLFSSL_SUCCESS;
    }

    return WOLFSSL_FAILURE;
}


int wolfSSL_BIO_seek(WOLFSSL_BIO *bio, int ofs)
{
      WOLFSSL_ENTER("wolfSSL_BIO_seek");

      if (bio == NULL) {
          return WOLFSSL_FATAL_ERROR;
      }

      /* offset ofs from beginning of file */
      if (bio->type == WOLFSSL_BIO_FILE &&
              XFSEEK(bio->ptr.fh, ofs, SEEK_SET) < 0) {
          return WOLFSSL_FATAL_ERROR;
      }

      return 0;
}
/* wolfSSL_BIO_tell is provided as compatible API with
 * BIO_tell which returns the current file position of a file related BIO.
 * Returns the current file position on success and -1 for failure.
 * Returns 0 for a BIOs except file related BIO.
 */
int wolfSSL_BIO_tell(WOLFSSL_BIO* bio)
{
    int pos;

    WOLFSSL_ENTER("wolfSSL_BIO_tell");

    if (bio == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    if (bio->type != WOLFSSL_BIO_FILE) {
        return 0;
    }

    pos = (int)XFTELL(bio->ptr.fh);
    if (pos < 0)
        return WOLFSSL_FATAL_ERROR;
    else
        return pos;
}
#endif /* NO_FILESYSTEM */


long wolfSSL_BIO_set_mem_eof_return(WOLFSSL_BIO *bio, int v)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_mem_eof_return");

    if (bio != NULL && bio->type == WOLFSSL_BIO_MEMORY) {
        bio->eof = v;
        return WOLFSSL_SUCCESS;
    }
    else
        return WOLFSSL_FAILURE;
}

int wolfSSL_BIO_get_len(WOLFSSL_BIO *bio)
{
    int len;
#ifndef NO_FILESYSTEM
    long memSz = 0;
    XFILE file;
#endif

    WOLFSSL_ENTER("wolfSSL_BIO_get_len");

    if (bio == NULL) {
        WOLFSSL_MSG("WOLFSSL_BIO was null");
        len = BAD_FUNC_ARG;
    }
    else if ((len = wolfSSL_BIO_pending(bio)) > 0) {
    }
#ifndef NO_FILESYSTEM
    else if (bio->type == WOLFSSL_BIO_FILE) {
        if (wolfSSL_BIO_get_fp(bio, &file) != WOLFSSL_SUCCESS)
            len = BAD_FUNC_ARG;
        if (len == 0) {
            len = wolfssl_file_len(file, &memSz);
        }
        if (len == 0) {
            len = (int)memSz;
        }
    }
#endif
    return len;
}


void wolfSSL_BIO_set_callback(WOLFSSL_BIO *bio, wolf_bio_info_cb callback_func)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_callback");

    if (bio != NULL) {
        bio->infoCb = callback_func;
    }
}


wolf_bio_info_cb wolfSSL_BIO_get_callback(WOLFSSL_BIO *bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_get_callback");

    if (bio != NULL) {
        return bio->infoCb;
    }

    return NULL;
}


void wolfSSL_BIO_set_callback_arg(WOLFSSL_BIO *bio, char *arg)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_callback_arg");

    if (bio != NULL) {
        bio->infoArg = arg;
    }
}


char* wolfSSL_BIO_get_callback_arg(const WOLFSSL_BIO *bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_get_callback_arg");

    if (bio != NULL) {
        return bio->infoArg;
    }

    return NULL;
}


/* store a user pointer in the WOLFSSL_BIO structure */
void wolfSSL_BIO_set_data(WOLFSSL_BIO* bio, void *ptr)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_data");

    if (bio != NULL) {
        bio->usrCtx = ptr;
    }
}


void* wolfSSL_BIO_get_data(WOLFSSL_BIO* bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_get_data");

    if (bio != NULL)
        return bio->usrCtx;

    WOLFSSL_MSG("WOLFSSL_BIO was null");
    return NULL;
}

/* If flag is 0 then blocking is set, if 1 then non blocking.
 * Always returns WOLFSSL_SUCCESS.
 */
long wolfSSL_BIO_set_nbio(WOLFSSL_BIO* bio, long on)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_nbio");

    if (bio) {
        switch (bio->type) {
            case WOLFSSL_BIO_SOCKET:
            case WOLFSSL_BIO_DGRAM:
            #ifdef XFCNTL
                {
                    int ret;
                    int flag = XFCNTL(bio->num.fd, F_GETFL, 0);
                    if (on) {
                        ret = XFCNTL(bio->num.fd, F_SETFL, flag | O_NONBLOCK);
                    }
                    else {
                        ret = XFCNTL(bio->num.fd, F_SETFL, flag & ~O_NONBLOCK);
                    }

                    if (ret == -1) {
                        WOLFSSL_MSG("Call to XFCNTL failed");
                    }
                }
            #endif
                break;
            case WOLFSSL_BIO_SSL:
            #ifdef WOLFSSL_DTLS
                wolfSSL_dtls_set_using_nonblock(bio->ptr.ssl, (int)on);
            #endif
                break;

            default:
                WOLFSSL_MSG("Unsupported bio type for non blocking");
                break;
        }
    }

    (void)on;

    return WOLFSSL_SUCCESS;
}

/* creates a new custom WOLFSSL_BIO_METHOD */
WOLFSSL_BIO_METHOD *wolfSSL_BIO_meth_new(int type, const char *name)
{
    WOLFSSL_BIO_METHOD* meth;

    WOLFSSL_ENTER("wolfSSL_BIO_meth_new");

    meth = (WOLFSSL_BIO_METHOD*)XMALLOC(sizeof(WOLFSSL_BIO_METHOD), NULL,
            DYNAMIC_TYPE_OPENSSL);
    if (meth == NULL) {
        WOLFSSL_MSG("Error allocating memory for WOLFSSL_BIO_METHOD");
        return NULL;
    }
    XMEMSET(meth, 0, sizeof(WOLFSSL_BIO_METHOD));
    meth->type = (byte)type;
    XSTRNCPY(meth->name, name, MAX_BIO_METHOD_NAME - 1);

    return meth;
}


void wolfSSL_BIO_meth_free(WOLFSSL_BIO_METHOD *biom)
{
    WOLFSSL_ENTER("wolfSSL_BIO_meth_free");
    XFREE(biom, NULL, DYNAMIC_TYPE_OPENSSL);
}


int wolfSSL_BIO_meth_set_write(WOLFSSL_BIO_METHOD *biom,
        wolfSSL_BIO_meth_write_cb biom_write)
{
    WOLFSSL_ENTER("wolfSSL_BIO_meth_set_write");
    if (biom) {
        biom->writeCb = biom_write;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}


int wolfSSL_BIO_meth_set_read(WOLFSSL_BIO_METHOD *biom,
        wolfSSL_BIO_meth_read_cb biom_read)
{
    WOLFSSL_ENTER("wolfSSL_BIO_meth_set_read");
    if (biom) {
        biom->readCb = biom_read;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}


int wolfSSL_BIO_meth_set_puts(WOLFSSL_BIO_METHOD *biom,
        wolfSSL_BIO_meth_puts_cb biom_puts)
{
    WOLFSSL_ENTER("wolfSSL_BIO_meth_set_puts");
    if (biom) {
        biom->putsCb = biom_puts;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}


int wolfSSL_BIO_meth_set_gets(WOLFSSL_BIO_METHOD *biom,
        wolfSSL_BIO_meth_gets_cb biom_gets)
{
    WOLFSSL_ENTER("wolfSSL_BIO_meth_set_gets");
    if (biom) {
        biom->getsCb = biom_gets;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}


int wolfSSL_BIO_meth_set_ctrl(WOLFSSL_BIO_METHOD *biom,
        wolfSSL_BIO_meth_ctrl_get_cb biom_ctrl)
{
    WOLFSSL_ENTER("wolfSSL_BIO_meth_set_ctrl");
    if (biom) {
        biom->ctrlCb = biom_ctrl;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}


int wolfSSL_BIO_meth_set_create(WOLFSSL_BIO_METHOD *biom,
        wolfSSL_BIO_meth_create_cb biom_create)
{
    WOLFSSL_ENTER("wolfSSL_BIO_meth_set_create");
    if (biom) {
        biom->createCb = biom_create;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}


int wolfSSL_BIO_meth_set_destroy(WOLFSSL_BIO_METHOD *biom,
        wolfSSL_BIO_meth_destroy_cb biom_destroy)
{
    WOLFSSL_ENTER("wolfSSL_BIO_meth_set_destroy");
    if (biom) {
        biom->freeCb = biom_destroy;
        return WOLFSSL_SUCCESS;
    }
    return WOLFSSL_FAILURE;
}


/* this compatibility function can be used for multiple BIO types */
int wolfSSL_BIO_get_mem_data(WOLFSSL_BIO* bio, void* p)
{
    WOLFSSL_BIO* mem_bio;

#ifdef WOLFSSL_DEBUG_OPENSSL
    WOLFSSL_ENTER("wolfSSL_BIO_get_mem_data");
#endif

    if (bio == NULL)
        return WOLFSSL_FATAL_ERROR;

    mem_bio = bio;
    /* Return pointer from last memory BIO in chain */
    while (bio->next) {
        bio = bio->next;
        if (bio->type == WOLFSSL_BIO_MEMORY)
            mem_bio = bio;
    }

    if (p) {
        *(byte**)p = mem_bio->ptr.mem_buf_data + mem_bio->rdIdx;
    }

    return mem_bio->wrSz - mem_bio->rdIdx;
}

int wolfSSL_BIO_pending(WOLFSSL_BIO* bio)
{
    return (int)wolfSSL_BIO_ctrl_pending(bio);
}


int wolfSSL_BIO_flush(WOLFSSL_BIO* bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_flush");

    if (bio == NULL)
        return WOLFSSL_FAILURE;

    if (bio->method != NULL && bio->method->ctrlCb != NULL) {
        WOLFSSL_MSG("Calling custom BIO flush callback");
        return (int)bio->method->ctrlCb(bio, WOLFSSL_BIO_CTRL_FLUSH, 0, NULL);
    }
    else if (bio->type == WOLFSSL_BIO_FILE) {
#if !defined(NO_FILESYSTEM) && defined(XFFLUSH)
        if (XFFLUSH(bio->ptr.fh) != 0)
            return WOLFSSL_FAILURE;

#endif /* !NO_FILESYSTEM && XFFLUSH */
    }
    return WOLFSSL_SUCCESS;
}


#ifdef OPENSSL_EXTRA

    WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_md(void)
    {
        static WOLFSSL_BIO_METHOD meth =
                WOLFSSL_BIO_METHOD_INIT(WOLFSSL_BIO_MD);

        WOLFSSL_ENTER("wolfSSL_BIO_f_md");

        return &meth;
    }

    /* return the context and initialize the BIO state */
    int wolfSSL_BIO_get_md_ctx(WOLFSSL_BIO *bio, WOLFSSL_EVP_MD_CTX **mdcp)
    {
        int ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);

        if ((bio != NULL) && (mdcp != NULL)) {
            *mdcp = bio->ptr.md_ctx;
            ret = WOLFSSL_SUCCESS;
        }

        if (ret == WOLFSSL_SUCCESS)
            return ret;
        else
            return WOLFSSL_FAILURE;
    }

    WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_buffer(void)
    {
        static WOLFSSL_BIO_METHOD meth =
                WOLFSSL_BIO_METHOD_INIT(WOLFSSL_BIO_BUFFER);

        WOLFSSL_ENTER("wolfSSL_BIO_f_buffer");

        return &meth;
    }

    #ifndef NO_WOLFSSL_STUB
    long wolfSSL_BIO_set_write_buffer_size(WOLFSSL_BIO* bio, long size)
    {
        /* wolfSSL has internal buffer, compatibility only */
        WOLFSSL_STUB("BIO_set_write_buffer_size");

        WOLFSSL_MSG("Buffer resize failed");

        (void)bio;
        (void)size;

        /* Even though this is only a STUB at the moment many user applications
         * may attempt to use this. OpenSSL documentation specifies the return
         * "return 1 if the buffer was successfully resized or 0 for failure."
         * since wolfSSL does not resize the buffer will always return failure
         * by default due to memory concerns until this stub is promoted to
         * a non-stub function */
        return WOLFSSL_FAILURE; /* 0, no resize happened */
    }
    #endif

    WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_bio(void)
    {
        static WOLFSSL_BIO_METHOD bio_meth =
                WOLFSSL_BIO_METHOD_INIT(WOLFSSL_BIO_BIO);

        WOLFSSL_ENTER("wolfSSL_BIO_s_bio");

        return &bio_meth;
    }


#ifndef NO_FILESYSTEM
    WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_file(void)
    {
        static WOLFSSL_BIO_METHOD file_meth =
                WOLFSSL_BIO_METHOD_INIT(WOLFSSL_BIO_FILE);

        WOLFSSL_ENTER("wolfSSL_BIO_s_file");

        return &file_meth;
    }
#endif


    WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_ssl(void)
    {
        static WOLFSSL_BIO_METHOD meth =
                WOLFSSL_BIO_METHOD_INIT(WOLFSSL_BIO_SSL);

        WOLFSSL_ENTER("wolfSSL_BIO_f_ssl");

        return &meth;
    }


    WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_socket(void)
    {
        static WOLFSSL_BIO_METHOD meth =
                WOLFSSL_BIO_METHOD_INIT(WOLFSSL_BIO_SOCKET);

        WOLFSSL_ENTER("wolfSSL_BIO_s_socket");

        return &meth;
    }


    WOLFSSL_BIO* wolfSSL_BIO_new_socket(int sfd, int closeF)
    {
        WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_socket());

        WOLFSSL_ENTER("wolfSSL_BIO_new_socket");
        if (bio) {
            bio->type  = WOLFSSL_BIO_SOCKET;
            bio->shutdown = (byte)closeF;
            bio->num.fd = (SOCKET_T)sfd;
        }
        return bio;
    }


#if defined(WOLFSSL_HAVE_BIO_ADDR) && defined(WOLFSSL_DTLS)
    WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_datagram(void)
    {
        static WOLFSSL_BIO_METHOD meth =
                WOLFSSL_BIO_METHOD_INIT(WOLFSSL_BIO_DGRAM);

        WOLFSSL_ENTER("wolfSSL_BIO_s_datagram");

        return &meth;
    }


    WOLFSSL_BIO* wolfSSL_BIO_new_dgram(int fd, int closeF)
    {
        WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_datagram());

        WOLFSSL_ENTER("wolfSSL_BIO_new_dgram");
        if (bio) {
            bio->type  = WOLFSSL_BIO_DGRAM;
            bio->shutdown = (byte)closeF;
            bio->num.fd = (SOCKET_T)fd;
        }
        return bio;
    }
#endif


    /**
     * Create new socket BIO object. This is a pure TCP connection with
     * no SSL or TLS protection.
     * @param str IP address to connect to
     * @return New BIO object or NULL on failure
     */
    WOLFSSL_BIO *wolfSSL_BIO_new_connect(const char *str)
    {
        WOLFSSL_BIO *bio;
        WOLFSSL_ENTER("wolfSSL_BIO_new_connect");
        bio = wolfSSL_BIO_new(wolfSSL_BIO_s_socket());
        if (bio) {
            const char* port = XSTRSTR(str, ":");

            if (port != NULL)
                bio->port = (word16)XATOI(port + 1);
            else
                port = str + XSTRLEN(str); /* point to null terminator */

            bio->ip = (char*)XMALLOC((port - str) + 1, /* +1 for null char */
                    bio->heap, DYNAMIC_TYPE_OPENSSL);
            if (bio->ip != NULL) {
                XMEMCPY(bio->ip, str, port - str);
                bio->ip[port - str] = '\0';
                bio->type  = WOLFSSL_BIO_SOCKET;
            }
            else {
                wolfSSL_BIO_free(bio);
                bio = NULL;
            }
        }
        return bio;
    }

    /**
     * Create new socket BIO object. This is a pure TCP connection with
     * no SSL or TLS protection.
     * @param port port  to connect to
     * @return New BIO object or NULL on failure
     */
    WOLFSSL_BIO *wolfSSL_BIO_new_accept(const char *port)
    {
        WOLFSSL_BIO *bio;
        WOLFSSL_ENTER("wolfSSL_BIO_new_accept");
        bio = wolfSSL_BIO_new(wolfSSL_BIO_s_socket());
        if (bio) {
            bio->port = (word16)XATOI(port);
            bio->type  = WOLFSSL_BIO_SOCKET;
        }
        return bio;
    }


    /**
     * Set the port to connect to in the BIO object
     * @param b BIO object
     * @param port destination port
     * @return WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on failure
     */
    long wolfSSL_BIO_set_conn_port(WOLFSSL_BIO *b, char* port)
    {
        int p;
        WOLFSSL_ENTER("wolfSSL_BIO_set_conn_port");

        if (!b || !port) {
            WOLFSSL_MSG("Bad parameter");
            return WOLFSSL_FAILURE;
        }

        p = XATOI(port);
        if (!p || p < 0) {
            WOLFSSL_MSG("Port parsing error");
            return WOLFSSL_FAILURE;
        }

        while (b != NULL && b->type != WOLFSSL_BIO_SOCKET) {
            b = b->next;
        }
        if (b == NULL) {
            WOLFSSL_MSG("Failed to find socket BIO in chain.");
            return WOLFSSL_FAILURE;
        }

        b->port = (word16)p;
        return WOLFSSL_SUCCESS;
    }

#ifdef HAVE_HTTP_CLIENT
    /**
     * Attempt to connect to the destination address and port
     * @param b BIO object
     * @return WOLFSSL_SUCCESS on success and WOLFSSL_FAILURE on failure
     */
    long wolfSSL_BIO_do_connect(WOLFSSL_BIO *b)
    {
        SOCKET_T sfd = SOCKET_INVALID;
        WOLFSSL_ENTER("wolfSSL_BIO_do_connect");

        if (!b) {
            WOLFSSL_MSG("Bad parameter");
            return WOLFSSL_FAILURE;
        }

        while (b && b->type != WOLFSSL_BIO_SOCKET)
            b = b->next;

        if (!b) {
            WOLFSSL_MSG("No socket BIO in chain");
            return WOLFSSL_FAILURE;
        }

        if (wolfIO_TcpConnect(&sfd, b->ip, b->port, 0) < 0 ) {
            WOLFSSL_MSG("wolfIO_TcpConnect error");
            return WOLFSSL_FAILURE;
        }

        b->num.fd = sfd;
        b->shutdown = WOLFSSL_BIO_CLOSE;
        return WOLFSSL_SUCCESS;
    }

#ifdef HAVE_SOCKADDR
    int wolfSSL_BIO_do_accept(WOLFSSL_BIO *b)
    {
        SOCKET_T sfd = SOCKET_INVALID;
        WOLFSSL_ENTER("wolfSSL_BIO_do_accept");

        if (!b) {
            WOLFSSL_MSG("Bad parameter");
            return WOLFSSL_FAILURE;
        }

        while (b && b->type != WOLFSSL_BIO_SOCKET)
            b = b->next;

        if (!b) {
            WOLFSSL_MSG("No socket BIO in chain");
            return WOLFSSL_FAILURE;
        }

        if (b->num.fd == SOCKET_INVALID) {
            if (wolfIO_TcpBind(&sfd, b->port) < 0) {
                WOLFSSL_MSG("wolfIO_TcpBind error");
                return WOLFSSL_FAILURE;
            }
            b->num.fd = sfd;
            b->shutdown = WOLFSSL_BIO_CLOSE;
        }
        else {
            WOLFSSL_BIO* new_bio;
            int newfd = wolfIO_TcpAccept(b->num.fd, NULL, NULL);
            if (newfd < 0) {
                WOLFSSL_MSG("wolfIO_TcpBind error");
                return WOLFSSL_FAILURE;
            }
            /* Create a socket BIO for using the accept'ed connection */
            new_bio = wolfSSL_BIO_new_socket(newfd, WOLFSSL_BIO_CLOSE);
            if (new_bio == NULL) {
                WOLFSSL_MSG("wolfSSL_BIO_new_socket error");
                CloseSocket(newfd);
                return WOLFSSL_FAILURE;
            }
            wolfSSL_BIO_set_callback(new_bio,
                    wolfSSL_BIO_get_callback(b));
            wolfSSL_BIO_set_callback_arg(new_bio,
                    wolfSSL_BIO_get_callback_arg(b));
            /* Push onto bio chain for user retrieval */
            if (wolfSSL_BIO_push(b, new_bio) == NULL) {
                WOLFSSL_MSG("wolfSSL_BIO_push error");
                /* newfd is closed when bio is free'd */
                wolfSSL_BIO_free(new_bio);
                return WOLFSSL_FAILURE;
            }
        }

        return WOLFSSL_SUCCESS;
    }
#endif /* HAVE_SOCKADDR */
#endif /* HAVE_HTTP_CLIENT */

    int wolfSSL_BIO_eof(WOLFSSL_BIO* b)
    {
        int ret = 0;
        WOLFSSL_ENTER("wolfSSL_BIO_eof");

        if (b == NULL)
            return 1; /* Undefined in OpenSSL. Let's signal we're done. */

        switch (b->type) {
            case WOLFSSL_BIO_SSL:
                ret = b->eof;
                break;
            default:
                ret = wolfSSL_BIO_get_len(b) == 0;
                break;
        }

        return ret;
    }

#ifndef NO_TLS
    long wolfSSL_BIO_do_handshake(WOLFSSL_BIO *b)
    {
        WOLFSSL_ENTER("wolfSSL_BIO_do_handshake");
        if (b == NULL) {
            WOLFSSL_MSG("Bad parameter");
            return WOLFSSL_FAILURE;
        }
        if (b->type == WOLFSSL_BIO_SSL && b->ptr.ssl != NULL) {
            return wolfSSL_negotiate(b->ptr.ssl);
        }
        else {
            WOLFSSL_MSG("Not SSL BIO or no SSL object set");
            return WOLFSSL_FAILURE;
        }
    }

    void wolfSSL_BIO_ssl_shutdown(WOLFSSL_BIO* b)
    {
        WOLFSSL_ENTER("wolfSSL_BIO_ssl_shutdown");

        if (b == NULL) {
            WOLFSSL_MSG("BIO is null.");
            return;
        }

        while (b != NULL && b->type != WOLFSSL_BIO_SSL) {
            b = b->next;
        }
        if (b == NULL) {
            WOLFSSL_MSG("Failed to find SSL BIO in chain.");
            return;
        }

        if (b->ptr.ssl != NULL) {
            int rc = wolfSSL_shutdown(b->ptr.ssl);
            if (rc == WOLFSSL_SHUTDOWN_NOT_DONE) {
                /* In this case, call again to give us a chance to read the
                 * close notify alert from the other end. */
                wolfSSL_shutdown(b->ptr.ssl);
            }
        }
        else {
            WOLFSSL_MSG("BIO has no SSL pointer set.");
        }
    }
#endif

    long wolfSSL_BIO_set_ssl(WOLFSSL_BIO* b, WOLFSSL* ssl, int closeF)
    {
        long ret = WC_NO_ERR_TRACE(WOLFSSL_FAILURE);

        WOLFSSL_ENTER("wolfSSL_BIO_set_ssl");

        if (b != NULL) {
            b->ptr.ssl = ssl;
            b->shutdown = (byte)closeF;
            if (b->next != NULL)
                wolfSSL_set_bio(ssl, b->next, b->next);
    /* add to ssl for bio free if SSL_free called before/instead of free_all? */
            ret = WOLFSSL_SUCCESS;
        }

        if (ret == WOLFSSL_SUCCESS)
            return ret;
        else
            return WOLFSSL_FAILURE;
    }

    long wolfSSL_BIO_get_ssl(WOLFSSL_BIO* bio, WOLFSSL** ssl)
    {
        WOLFSSL_ENTER("wolfSSL_BIO_get_ssl");

        if (bio == NULL) {
            WOLFSSL_MSG("bio is null.");
            return WOLFSSL_FAILURE;
        }
        if (ssl == NULL) {
            WOLFSSL_MSG("ssl is null.");
            return WOLFSSL_FAILURE;
        }
        if (bio->type != WOLFSSL_BIO_SSL) {
            WOLFSSL_MSG("bio type is not WOLFSSL_BIO_SSL.");
            return WOLFSSL_FAILURE;
        }

        *ssl = bio->ptr.ssl;

        return WOLFSSL_SUCCESS;
    }

    WOLFSSL_BIO* wolfSSL_BIO_new_ssl(WOLFSSL_CTX* ctx, int client)
    {
        WOLFSSL* ssl = NULL;
        WOLFSSL_BIO* sslBio = NULL;
        int err = 0;

        WOLFSSL_ENTER("wolfSSL_BIO_new_ssl");

        if (ctx == NULL) {
            WOLFSSL_MSG("ctx is NULL.");
            err = 1;
        }

        if (err == 0) {
            ssl = wolfSSL_new(ctx);
            if (ssl == NULL) {
                WOLFSSL_MSG("Failed to create SSL object from ctx.");
                err = 1;
            }
        }
        if (err == 0) {
            sslBio = wolfSSL_BIO_new(wolfSSL_BIO_f_ssl());
            if (sslBio == NULL) {
                WOLFSSL_MSG("Failed to create SSL BIO.");
                err = 1;
            }
        }
        if (err == 0) {
            if (!client)
                wolfSSL_set_accept_state(ssl);
            else
                wolfSSL_set_connect_state(ssl);
        }
        if (err == 0 && wolfSSL_BIO_set_ssl(sslBio, ssl, WOLFSSL_BIO_CLOSE) !=
            WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Failed to set SSL pointer in BIO.");
            err = 1;
        }

        if (err) {
            wolfSSL_free(ssl);
            wolfSSL_BIO_free(sslBio);
        }

        return sslBio;
    }

    WOLFSSL_BIO* wolfSSL_BIO_new_ssl_connect(WOLFSSL_CTX* ctx)
    {
        WOLFSSL_BIO* sslBio = NULL;
        WOLFSSL_BIO* connBio = NULL;
        int err = 0;

        WOLFSSL_ENTER("wolfSSL_BIO_new_ssl_connect");

        if (ctx == NULL) {
            WOLFSSL_MSG("ctx is NULL.");
            err = 1;
        }

        if (err == 0) {
            sslBio = wolfSSL_BIO_new_ssl(ctx, 1);
            if (sslBio == NULL) {
                WOLFSSL_MSG("Failed to create SSL BIO.");
                err = 1;
            }
        }
        if (err == 0) {
            connBio = wolfSSL_BIO_new(wolfSSL_BIO_s_socket());
            if (connBio == NULL) {
                WOLFSSL_MSG("Failed to create connect BIO.");
                err = 1;
            }
            else {
                wolfSSL_BIO_push(sslBio, connBio);
            }
        }

        if (err == 1) {
            wolfSSL_BIO_free(sslBio);
            sslBio = NULL;
            wolfSSL_BIO_free(connBio);
        }

        return sslBio;
    }

    long wolfSSL_BIO_set_conn_hostname(WOLFSSL_BIO* b, char* name)
    {
        size_t newLen = 0;

        WOLFSSL_ENTER("wolfSSL_BIO_set_conn_hostname");

        if (name == NULL) {
            WOLFSSL_MSG("Hostname is NULL.");
            return WOLFSSL_FAILURE;
        }

        while (b != NULL && b->type != WOLFSSL_BIO_SOCKET) {
            b = b->next;
        }
        if (b == NULL) {
            WOLFSSL_MSG("Failed to find socket BIO in chain.");
            return WOLFSSL_FAILURE;
        }

        newLen = XSTRLEN(name);
        if (b->ip == NULL) {
            /* +1 for null char */
            b->ip = (char*)XMALLOC(newLen + 1, b->heap, DYNAMIC_TYPE_OPENSSL);
            if (b->ip == NULL) {
                WOLFSSL_MSG("Hostname malloc failed.");
                return WOLFSSL_FAILURE;
            }
        }
        else {
            size_t currLen = XSTRLEN(b->ip);
        #ifdef WOLFSSL_NO_REALLOC
            char* tmp = NULL;
        #endif

            if (currLen != newLen) {
        #ifdef WOLFSSL_NO_REALLOC
                tmp = b->ip;
                b->ip = (char*)XMALLOC(newLen+1, b->heap, DYNAMIC_TYPE_OPENSSL);
                if (b->ip != NULL && tmp != NULL) {
                    XMEMCPY(b->ip, tmp, newLen);
                    XFREE(tmp, b->heap, DYNAMIC_TYPE_OPENSSL);
                    tmp = NULL;
            }
        #else
                b->ip = (char*)XREALLOC(b->ip, newLen + 1, b->heap,
                    DYNAMIC_TYPE_OPENSSL);
        #endif
                if (b->ip == NULL) {
                    WOLFSSL_MSG("Hostname realloc failed.");
                    return WOLFSSL_FAILURE;
                }
            }
        }

        XMEMCPY(b->ip, name, newLen);
        b->ip[newLen] = '\0';

        return WOLFSSL_SUCCESS;
    }

#ifndef NO_FILESYSTEM
    long wolfSSL_BIO_set_fd(WOLFSSL_BIO* b, int fd, int closeF)
    {
        WOLFSSL_ENTER("wolfSSL_BIO_set_fd");

        if (b != NULL) {
            b->num.fd = (SOCKET_T)fd;
            b->shutdown = (byte)closeF;
        }

        return WOLFSSL_SUCCESS;
    }
#endif

    /* Sets the close flag */
    int wolfSSL_BIO_set_close(WOLFSSL_BIO *b, long flag)
    {
        WOLFSSL_ENTER("wolfSSL_BIO_set_close");
        if (b != NULL) {
            b->shutdown = (byte)flag;
        }

        return WOLFSSL_SUCCESS;
    }

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    WOLFSSL_BIO* wolfSSL_BIO_new(const WOLFSSL_BIO_METHOD* method)
#else
    WOLFSSL_BIO* wolfSSL_BIO_new(WOLFSSL_BIO_METHOD* method)
#endif
    {
        WOLFSSL_BIO* bio;

        WOLFSSL_ENTER("wolfSSL_BIO_new");
        if (method == NULL) {
            WOLFSSL_MSG("Bad method pointer passed in");
            return NULL;
        }

        bio = (WOLFSSL_BIO*) XMALLOC(sizeof(WOLFSSL_BIO), 0,
                DYNAMIC_TYPE_OPENSSL);
        if (bio) {
            XMEMSET(bio, 0, sizeof(WOLFSSL_BIO));
            bio->type = (byte)method->type;
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
            bio->method = (WOLFSSL_BIO_METHOD*)method;
#else
            bio->method = method;
#endif
            bio->shutdown = WOLFSSL_BIO_CLOSE; /* default to close things */

            if ((bio->type == WOLFSSL_BIO_SOCKET) ||
                (bio->type == WOLFSSL_BIO_DGRAM))
            {
                bio->num.fd = SOCKET_INVALID;
            }
            else if (bio->type == WOLFSSL_BIO_FILE) {
#ifndef NO_FILESYSTEM
                bio->ptr.fh = XBADFILE;
#endif
                bio->num.fd = SOCKET_INVALID;
            }
            else {
                bio->num.length = 0;
            }
            bio->init = 1;

        #if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
            {
                int ret;
                wolfSSL_RefInit(&bio->ref, &ret);
            #ifdef WOLFSSL_REFCNT_ERROR_RETURN
                if (ret != 0) {
                    wolfSSL_BIO_free(bio);
                    WOLFSSL_MSG("wc_InitMutex failed for WOLFSSL_BIO");
                    return NULL;
                }
            #else
                (void)ret;
            #endif
            }
        #endif

            if (method->type == WOLFSSL_BIO_MEMORY)
                bio->eof = WOLFSSL_BIO_ERROR; /* Return value for empty buffer */
            if (method->type == WOLFSSL_BIO_MEMORY ||
                    method->type == WOLFSSL_BIO_BIO) {
                bio->mem_buf = wolfSSL_BUF_MEM_new();
                if (bio->mem_buf == NULL) {
                    WOLFSSL_MSG("Memory error");
                    wolfSSL_BIO_free(bio);
                    return NULL;
                }
            }

            if (method->type == WOLFSSL_BIO_MD) {
                bio->ptr.md_ctx = wolfSSL_EVP_MD_CTX_new();
                if (bio->ptr.md_ctx == NULL) {
                    WOLFSSL_MSG("Memory error");
                    wolfSSL_BIO_free(bio);
                    return NULL;
                }
            }

            /* check if is custom method */
            if (method->createCb) {
                method->createCb(bio);
            }

        }
        return bio;
    }

    WOLFSSL_BIO* wolfSSL_BIO_new_mem_buf(const void* buf, int len)
    {
        WOLFSSL_BIO* bio = NULL;

        if (buf == NULL) {
            return bio;
        }

        bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
        if (bio == NULL) {
            return bio;
        }

        if (len < 0) {
            /* The length of the string including terminating null. */
            len = (int)XSTRLEN((const char*)buf) + 1;
        }

        if (len > 0 && wolfSSL_BUF_MEM_resize(bio->mem_buf, (size_t)len) == 0) {
            wolfSSL_BIO_free(bio);
            return NULL;
        }

        bio->num.length = bio->mem_buf->max;
        bio->wrSz = len;
        bio->ptr.mem_buf_data = (byte *)bio->mem_buf->data;
        if (len > 0 && bio->ptr.mem_buf_data != NULL) {
            XMEMCPY(bio->ptr.mem_buf_data, buf, len);
            bio->flags |= WOLFSSL_BIO_FLAG_MEM_RDONLY;
            bio->wrSzReset = bio->wrSz;
        }

        return bio;
    }

    /*
     * Note : If the flag BIO_NOCLOSE is set then freeing memory buffers is up
     *        to the application.
     * Returns 1 on success, 0 on failure
     */
    int wolfSSL_BIO_free(WOLFSSL_BIO* bio)
    {
        int ret;
    #if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
        int doFree = 0;
    #endif

        /* unchain?, doesn't matter in goahead since from free all */
        WOLFSSL_ENTER("wolfSSL_BIO_free");
        if (bio) {

            if (bio->infoCb) {
                /* info callback is called before free */
                ret = (int)bio->infoCb(bio, WOLFSSL_BIO_CB_FREE, NULL, 0, 0, 1);
                if (ret <= 0) {
                    return ret;
                }
            }

    #if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA)
            wolfSSL_RefDec(&bio->ref, &doFree, &ret);

            if (!doFree) {
                /* return success if BIO ref count is not 1 yet */
            #ifdef WOLFSSL_REFCNT_ERROR_RETURN
                return (ret == 0) ? WOLFSSL_SUCCESS : WOLFSSL_FAILURE ;
            #else
                (void)ret;
                return WOLFSSL_SUCCESS;
            #endif
            }
        #ifndef SINGLE_THREADED
            wolfSSL_RefFree(&bio->ref);
        #endif
    #endif

        #ifdef HAVE_EX_DATA_CLEANUP_HOOKS
            wolfSSL_CRYPTO_cleanup_ex_data(&bio->ex_data);
        #endif

            /* call custom set free callback */
            if (bio->method && bio->method->freeCb) {
                bio->method->freeCb(bio);
            }

            /* remove from pair by setting the paired bios pair to NULL */
            if (bio->pair != NULL) {
                bio->pair->pair = NULL;
            }

            XFREE(bio->ip, bio->heap, DYNAMIC_TYPE_OPENSSL);

            if (bio->shutdown) {
                if (bio->type == WOLFSSL_BIO_SSL && bio->ptr.ssl)
                    wolfSSL_free(bio->ptr.ssl);
            #ifdef CloseSocket
                if (((bio->type == WOLFSSL_BIO_SOCKET) ||
                     (bio->type == WOLFSSL_BIO_DGRAM)) &&
                    (bio->num.fd != SOCKET_INVALID))
                {
                    CloseSocket(bio->num.fd);
                }
            #endif
            }

        #ifndef NO_FILESYSTEM
            if (bio->type == WOLFSSL_BIO_FILE &&
                bio->shutdown == WOLFSSL_BIO_CLOSE)
            {
                if (bio->ptr.fh) {
                    XFCLOSE(bio->ptr.fh);
                }
            #if !defined(USE_WINDOWS_API) && !defined(NO_WOLFSSL_DIR)\
                && !defined(WOLFSSL_NUCLEUS) && !defined(WOLFSSL_NUCLEUS_1_2)
                else if (bio->num.fd != SOCKET_INVALID) {
                    XCLOSE(bio->num.fd);
                }
            #endif
            }
        #endif

            if (bio->shutdown != WOLFSSL_BIO_NOCLOSE) {
                if (bio->type == WOLFSSL_BIO_MEMORY &&
                    bio->ptr.mem_buf_data != NULL)
                {
                    if (bio->mem_buf != NULL) {
                        if ((byte *)bio->mem_buf->data != bio->ptr.mem_buf_data)
                        {
                            XFREE(bio->ptr.mem_buf_data, bio->heap,
                                  DYNAMIC_TYPE_OPENSSL);
                            bio->ptr.mem_buf_data = NULL;
                        }
                    }
                    else {
                        XFREE(bio->ptr.mem_buf_data, bio->heap,
                              DYNAMIC_TYPE_OPENSSL);
                        bio->ptr.mem_buf_data = NULL;
                    }
                }
                if (bio->mem_buf != NULL) {
                    wolfSSL_BUF_MEM_free(bio->mem_buf);
                    bio->mem_buf = NULL;
                }
            }

            if (bio->type == WOLFSSL_BIO_MD) {
                wolfSSL_EVP_MD_CTX_free(bio->ptr.md_ctx);
            }

            XFREE(bio, 0, DYNAMIC_TYPE_OPENSSL);
            return WOLFSSL_SUCCESS;
        }
        return WOLFSSL_FAILURE;
    }

    /* like BIO_free, but no return value */
    void wolfSSL_BIO_vfree(WOLFSSL_BIO* bio)
    {
        wolfSSL_BIO_free(bio);
    }


    void wolfSSL_BIO_free_all(WOLFSSL_BIO* bio)
    {
        WOLFSSL_ENTER("wolfSSL_BIO_free_all");
        while (bio) {
            WOLFSSL_BIO* next = bio->next;
            wolfSSL_BIO_free(bio);
            bio = next;
        }
    }


    WOLFSSL_BIO* wolfSSL_BIO_push(WOLFSSL_BIO* top, WOLFSSL_BIO* append)
    {
        WOLFSSL_ENTER("wolfSSL_BIO_push");
        if (top == NULL) {
            return append;
        }
        top->next = append;
        if (append != NULL) {
            append->prev = top;
        }

        /* SSL BIO's should use the next object in the chain for IO */
        if (top->type == WOLFSSL_BIO_SSL && top->ptr.ssl)
            wolfSSL_set_bio(top->ptr.ssl, append, append);

        return top;
    }

/* Removes a WOLFSSL_BIO struct from the WOLFSSL_BIO linked list.
 *
 * bio is the WOLFSSL_BIO struct in the list and removed.
 *
 * The return WOLFSSL_BIO struct is the next WOLFSSL_BIO in the list or NULL if
 * there is none.
 */
WOLFSSL_BIO* wolfSSL_BIO_pop(WOLFSSL_BIO* bio)
{
    if (bio == NULL) {
        WOLFSSL_MSG("Bad argument passed in");
        return NULL;
    }

    if (bio->prev != NULL) {
        bio->prev->next = bio->next;
    }

    if (bio->next != NULL) {
        bio->next->prev = bio->prev;
    }

    return bio->next;
}



WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_mem(void)
{
    static WOLFSSL_BIO_METHOD meth =
            WOLFSSL_BIO_METHOD_INIT(WOLFSSL_BIO_MEMORY);

    WOLFSSL_ENTER("wolfSSL_BIO_s_mem");

    return &meth;
}


WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_base64(void)
{
    static WOLFSSL_BIO_METHOD meth =
            WOLFSSL_BIO_METHOD_INIT(WOLFSSL_BIO_BASE64);

    WOLFSSL_ENTER("wolfSSL_BIO_f_base64");

    return &meth;
}


/* Set the flag for the bio.
 *
 * bio   the structure to set the flag in
 * flags the flag to use
 */
void wolfSSL_BIO_set_flags(WOLFSSL_BIO* bio, int flags)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_flags");

    if (bio != NULL) {
        bio->flags |= flags;
    }
}

void wolfSSL_BIO_clear_flags(WOLFSSL_BIO *bio, int flags)
{
    WOLFSSL_ENTER("wolfSSL_BIO_clear_flags");
    if (bio != NULL) {
        bio->flags &= ~flags;
    }
}

/* Set ex_data for WOLFSSL_BIO
 *
 * bio  : BIO structure to set ex_data in
 * idx  : Index of ex_data to set
 * data : Data to set in ex_data
 *
 * Returns WOLFSSL_SUCCESS on success or WOLFSSL_FAILURE on failure
 */
int wolfSSL_BIO_set_ex_data(WOLFSSL_BIO *bio, int idx, void *data)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_ex_data");
#ifdef HAVE_EX_DATA
    if (bio != NULL && idx < MAX_EX_DATA) {
        return wolfSSL_CRYPTO_set_ex_data(&bio->ex_data, idx, data);
    }
#else
    (void)bio;
    (void)idx;
    (void)data;
#endif
    return WOLFSSL_FAILURE;
}

int wolfSSL_BIO_get_fd(WOLFSSL_BIO *bio, int* fd)
{
    WOLFSSL_ENTER("wolfSSL_BIO_get_fd");

    if (bio != NULL) {
        if (bio->num.fd == SOCKET_INVALID)
            return WOLFSSL_BIO_ERROR;
        if (fd != NULL)
            *fd = (int)bio->num.fd;
        return (int)bio->num.fd;
    }

    return WOLFSSL_BIO_ERROR;
}

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
/* Set ex_data for WOLFSSL_BIO
 *
 * bio  : BIO structure to set ex_data in
 * idx  : Index of ex_data to set
 * data : Data to set in ex_data
 * cleanup_routine : Function pointer to clean up data
 *
 * Returns WOLFSSL_SUCCESS on success or WOLFSSL_FAILURE on failure
 */
int wolfSSL_BIO_set_ex_data_with_cleanup(
    WOLFSSL_BIO *bio,
    int idx,
    void *data,
    wolfSSL_ex_data_cleanup_routine_t cleanup_routine)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_ex_data_with_cleanup");
    if (bio != NULL && idx < MAX_EX_DATA) {
        return wolfSSL_CRYPTO_set_ex_data_with_cleanup(&bio->ex_data, idx, data,
                                                       cleanup_routine);
    }
    return WOLFSSL_FAILURE;
}
#endif /* HAVE_EX_DATA_CLEANUP_HOOKS */

/* Get ex_data in WOLFSSL_BIO at given index
 *
 * bio  : BIO structure to get ex_data from
 * idx  : Index of ex_data to get data from
 *
 * Returns void pointer to ex_data on success or NULL on failure
 */
void *wolfSSL_BIO_get_ex_data(WOLFSSL_BIO *bio, int idx)
{
    WOLFSSL_ENTER("wolfSSL_BIO_get_ex_data");
#ifdef HAVE_EX_DATA
    if (bio != NULL && idx < MAX_EX_DATA && idx >= 0) {
        return wolfSSL_CRYPTO_get_ex_data(&bio->ex_data, idx);
    }
#else
    (void)bio;
    (void)idx;
#endif
    return NULL;
}

#endif /* OPENSSL_EXTRA */

#ifndef NO_FILESYSTEM
    PRAGMA_CLANG_DIAG_PUSH
    PRAGMA_CLANG("clang diagnostic ignored \"-Wformat-nonliteral\"")
#endif

#if defined(OPENSSL_EXTRA)
/* returns amount printed on success, negative in fail case */
#ifdef __clang__
/* tell clang argument 2 is format */
__attribute__((__format__ (__printf__, 2, 0)))
#endif
int wolfSSL_BIO_vprintf(WOLFSSL_BIO* bio, const char* format, va_list args)
{
    int ret = -1;

    if (bio == NULL)
        return WOLFSSL_FATAL_ERROR;

    switch (bio->type) {
#if !defined(NO_FILESYSTEM)
        case WOLFSSL_BIO_FILE:
            if (bio->ptr.fh == XBADFILE) {
                return WOLFSSL_FATAL_ERROR;
            }
            ret = XVFPRINTF(bio->ptr.fh, format, args);
            break;
#endif

        case WOLFSSL_BIO_MEMORY:
    /* In Visual Studio versions prior to Visual Studio 2013, the va_* symbols
       aren't defined. If using Visual Studio 2013 or later, define
       HAVE_VA_COPY. */
    #if !defined(_WIN32) || defined(HAVE_VA_COPY)
        case WOLFSSL_BIO_SSL:
            {
                int count;
                char* pt = NULL;
                va_list copy;

                #ifdef FUSION_RTOS
                   copy = args;    /* hack, depends on internal implementation
                                    * of va_list in VisualDSP++ */
                #else
                    va_copy(copy, args);
                #endif
                count = XVSNPRINTF(NULL, 0, format, args);
                if (count >= 0)
                {
                    pt = (char*)XMALLOC(count + 1, bio->heap,
                                        DYNAMIC_TYPE_TMP_BUFFER);
                    if (pt != NULL)
                    {
                        count = XVSNPRINTF(pt, count + 1, format, copy);
                        if (count >= 0)
                        {
                            ret = wolfSSL_BIO_write(bio, pt, count);
                        }
                        XFREE(pt, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
                    }
                }
                va_end(copy);
            }
            break;
    #endif /* !_WIN32 || HAVE_VA_COPY */

        default:
            WOLFSSL_MSG("Unsupported WOLFSSL_BIO type for wolfSSL_BIO_printf");
            break;
    }

    return ret;
}

/* returns amount printed on success, negative in fail case */
#ifdef __clang__
/* tell clang argument 2 is format */
__attribute__((__format__ (__printf__, 2, 0)))
#endif
int wolfSSL_BIO_printf(WOLFSSL_BIO* bio, const char* format, ...)
{
    int ret;
    va_list args;
    va_start(args, format);

    ret = wolfSSL_BIO_vprintf(bio, format, args);

    va_end(args);

    return ret;
}

#ifndef NO_FILESYSTEM
    PRAGMA_CLANG_DIAG_POP
#endif

#undef  BIO_DUMP_LINE_LEN
#define BIO_DUMP_LINE_LEN 16
int wolfSSL_BIO_dump(WOLFSSL_BIO *bio, const char *buf, int length)
{
    int ret = 0;
#ifndef NO_FILESYSTEM
    int lineOffset = 0;
#endif

    if (bio == NULL)
        return 0;

#ifndef NO_FILESYSTEM
    do
    {
        int i;
        char line[80];
        int o;

        if (!buf) {
            return wolfSSL_BIO_write(bio, "\tNULL", 5);
        }

        (void)XSNPRINTF(line, sizeof(line), "%04x - ", lineOffset);
        o = 7;
        for (i = 0; i < BIO_DUMP_LINE_LEN; i++) {
            if (i < length)
                (void)XSNPRINTF(line + o, (int)sizeof(line) - o,
                    "%02x ", (unsigned char)buf[i]);
            else
                (void)XSNPRINTF(line + o, (int)sizeof(line) - o, "   ");
            if (i == 7)
                (void)XSNPRINTF(line + o + 2, (int)sizeof(line) - (o + 2), "-");
            o += 3;
        }
        (void)XSNPRINTF(line + o, (int)sizeof(line) - o, "  ");
        o += 2;
        for (i = 0; (i < BIO_DUMP_LINE_LEN) && (i < length); i++) {
            (void)XSNPRINTF(line + o, (int)sizeof(line) - o, "%c",
                     ((31 < buf[i]) && (buf[i] < 127)) ? buf[i] : '.');
            o++;
        }

        line[o++] = '\n';
        ret += wolfSSL_BIO_write(bio, line, o);

        buf += BIO_DUMP_LINE_LEN;
        length -= BIO_DUMP_LINE_LEN;
        lineOffset += BIO_DUMP_LINE_LEN;
    }
    while (length > 0);
#else
    (void)buf;
    (void)length;
#endif

    return ret;
}
#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(HAVE_LIGHTY) || \
    defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(HAVE_STUNNEL) || \
    defined(WOLFSSL_NGINX) || defined(HAVE_POCO_LIB) || \
    defined(WOLFSSL_HAPROXY)

    int wolfSSL_BIO_read_filename(WOLFSSL_BIO *b, const char *name) {
    #ifndef NO_FILESYSTEM
        XFILE fp;

        WOLFSSL_ENTER("wolfSSL_BIO_new_file");

        if ((wolfSSL_BIO_get_fp(b, &fp) == WOLFSSL_SUCCESS) && (fp != XBADFILE))
        {
            XFCLOSE(fp);
        }

        fp = XFOPEN(name, "rb");
        if (fp == XBADFILE)
            return WOLFSSL_BAD_FILE;

        if (wolfSSL_BIO_set_fp(b, fp, WOLFSSL_BIO_CLOSE) != WOLFSSL_SUCCESS) {
            XFCLOSE(fp);
            return WOLFSSL_BAD_FILE;
        }

        /* file is closed when bio is free'd */
        return WOLFSSL_SUCCESS;
    #else
        (void)name;
        (void)b;
        return WOLFSSL_NOT_IMPLEMENTED;
    #endif
    }

#endif

#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL) \
    || defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(OPENSSL_EXTRA)

WOLFSSL_BIO *wolfSSL_BIO_new_file(const char *filename, const char *mode)
{
#ifndef NO_FILESYSTEM
    WOLFSSL_BIO* bio;
    XFILE fp;

    WOLFSSL_ENTER("wolfSSL_BIO_new_file");

    fp = XFOPEN(filename, mode);
    if (fp == XBADFILE)
        return NULL;

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    if (bio == NULL) {
        XFCLOSE(fp);
        return bio;
    }

    if (wolfSSL_BIO_set_fp(bio, fp, WOLFSSL_BIO_CLOSE) != WOLFSSL_SUCCESS) {
        XFCLOSE(fp);
        wolfSSL_BIO_free(bio);
        bio = NULL;
    }

    /* file is closed when BIO is free'd */
    return bio;
#else
    (void)filename;
    (void)mode;
    return NULL;
#endif /* NO_FILESYSTEM */
}

#ifndef NO_FILESYSTEM
WOLFSSL_BIO* wolfSSL_BIO_new_fp(XFILE fp, int close_flag)
{
    WOLFSSL_BIO* bio;

    WOLFSSL_ENTER("wolfSSL_BIO_new_fp");

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    if (bio == NULL) {
        return bio;
    }

    if (wolfSSL_BIO_set_fp(bio, fp, close_flag) != WOLFSSL_SUCCESS) {
        wolfSSL_BIO_free(bio);
        bio = NULL;
    }

    /* file is closed when BIO is free'd or by user depending on flag */
    return bio;
}
#endif
#endif

#if defined(OPENSSL_ALL) || defined(WOLFSSL_ASIO) || defined(WOLFSSL_HAPROXY) \
    || defined(WOLFSSL_NGINX) || defined(WOLFSSL_QT)

/* Creates a new bio pair.
Returns WOLFSSL_SUCCESS if no error, WOLFSSL_FAILURE otherwise.*/
int wolfSSL_BIO_new_bio_pair(WOLFSSL_BIO **bio1_p, size_t writebuf1,
                                         WOLFSSL_BIO **bio2_p, size_t writebuf2)
{
    WOLFSSL_BIO *bio1 = NULL, *bio2 = NULL;
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_BIO_new_bio_pair");

    if (bio1_p == NULL || bio2_p == NULL) {
        WOLFSSL_MSG("Bad Function Argument");
        return BAD_FUNC_ARG;
    }

    /* set up the new bio structures and write buf sizes */
    if ((bio1 = wolfSSL_BIO_new(wolfSSL_BIO_s_bio())) == NULL) {
        WOLFSSL_MSG("Bio allocation failed");
        ret = WOLFSSL_FAILURE;
    }
    if (ret) {
        if ((bio2 = wolfSSL_BIO_new(wolfSSL_BIO_s_bio())) == NULL) {
            WOLFSSL_MSG("Bio allocation failed");
            ret = WOLFSSL_FAILURE;
        }
    }
    if (ret && writebuf1) {
        if (!(ret = wolfSSL_BIO_set_write_buf_size(bio1, (long)writebuf1))) {
            WOLFSSL_MSG("wolfSSL_BIO_set_write_buf() failure");
        }
    }
    if (ret && writebuf2) {
        if (!(ret = wolfSSL_BIO_set_write_buf_size(bio2, (long)writebuf2))) {
            WOLFSSL_MSG("wolfSSL_BIO_set_write_buf() failure");
        }
    }

    if (ret) {
        if ((ret = wolfSSL_BIO_make_bio_pair(bio1, bio2))) {
            *bio1_p = bio1;
            *bio2_p = bio2;
        }
    }
    if (!ret) {
        wolfSSL_BIO_free(bio1);
        bio1 = NULL;
        wolfSSL_BIO_free(bio2);
        bio2 = NULL;
    }
    return ret;
}

#endif

#ifdef OPENSSL_ALL

#ifndef NO_WOLFSSL_STUB
void wolfSSL_BIO_set_init(WOLFSSL_BIO* bio, int init)
{
    WOLFSSL_STUB("wolfSSL_BIO_set_init");
    (void)bio;
    (void)init;
}
#endif /* NO_WOLFSSL_STUB */

void wolfSSL_BIO_set_shutdown(WOLFSSL_BIO* bio, int shut)
{
    WOLFSSL_ENTER("wolfSSL_BIO_set_shutdown");
    if (bio != NULL)
        bio->shutdown = (byte)shut;
}

int wolfSSL_BIO_get_shutdown(WOLFSSL_BIO* bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_get_shutdown");
    return bio != NULL && bio->shutdown;
}

void wolfSSL_BIO_clear_retry_flags(WOLFSSL_BIO* bio)
{
    WOLFSSL_ENTER("wolfSSL_BIO_clear_retry_flags");

    if (bio)
        bio->flags &= ~(WOLFSSL_BIO_FLAG_READ | WOLFSSL_BIO_FLAG_WRITE |
                        WOLFSSL_BIO_FLAG_RETRY);
}

int wolfSSL_BIO_should_retry(WOLFSSL_BIO *bio)
{
    int ret = 0;
    if (bio != NULL) {
        ret = (int)(bio->flags & WOLFSSL_BIO_FLAG_RETRY);
    }

    return ret;
}

int wolfSSL_BIO_should_read(WOLFSSL_BIO *bio)
{
    int ret = 0;
    if (bio != NULL) {
        ret = (int)(bio->flags & WOLFSSL_BIO_FLAG_READ);
    }

    return ret;
}

int wolfSSL_BIO_should_write(WOLFSSL_BIO *bio)
{
    int ret = 0;
    if (bio != NULL) {
        ret = (int)(bio->flags & WOLFSSL_BIO_FLAG_WRITE);
    }

    return ret;
}

#endif /* OPENSSL_ALL */

#endif /* WOLFSSL_BIO_INCLUDED */
