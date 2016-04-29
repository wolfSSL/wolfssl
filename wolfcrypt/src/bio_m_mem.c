/* bio_m_mem.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef OPENSSL_EXTRA

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/openssl/bio.h>


/* wolfSSL buffer type */
typedef struct {
    byte*  data;
    word32 length;
} WOLFCRYPT_BUF_MEM;

static WOLFCRYPT_BUF_MEM *WOLFCRYPT_BUF_MEM_new(void)
{
    WOLFCRYPT_BUF_MEM *buf;

    buf = (WOLFCRYPT_BUF_MEM *)XMALLOC(sizeof(WOLFCRYPT_BUF_MEM),
                                       0, DYNAMIC_TYPE_OPENSSL);
    if (buf == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return NULL;
    }

    buf->length = 0;
    buf->data = NULL;
    return buf;
}

static void WOLFCRYPT_BUF_MEM_free(WOLFCRYPT_BUF_MEM *buf)
{
    if (buf == NULL)
        return;

    if (buf->data != NULL) {
        XMEMSET(buf->data, 0, buf->length);
        XFREE(buf->data, 0, DYNAMIC_TYPE_OPENSSL);
    }

    XFREE(buf, 0, DYNAMIC_TYPE_OPENSSL);
}

static int WOLFCRYPT_BUF_MEM_grow(WOLFCRYPT_BUF_MEM *buf, size_t len)
{
    if (buf == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    /* size reduction, clean unused */
    if (buf->length >= len) {
        if (buf->data == NULL) {
            WOLFSSL_ERROR(BAD_FUNC_ARG);
            return -1;
        }

        buf->length = (word32)len;
        return (int)len;
    }

    if (buf->data == NULL)
        buf->data = XMALLOC(len, 0, DYNAMIC_TYPE_OPENSSL);
    else
        buf->data = XREALLOC(buf->data, buf->length+len,
                             0, DYNAMIC_TYPE_OPENSSL);
    if (buf->data == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return -1;
    }

    XMEMSET(&buf->data[buf->length], 0, len - buf->length);
    buf->length = (word32)len;

    return (int)len;
}

static int WOLFCRYPT_BUF_MEM_grow_clean(WOLFCRYPT_BUF_MEM *buf, size_t len)
{
    int ret, idx = -1;
    size_t size;

    if (buf == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    if (buf->length >= len) {
        idx = buf->length;
        size = buf->length - len;
    }

    ret = WOLFCRYPT_BUF_MEM_grow(buf, len);
    if (ret && idx != -1)
        XMEMSET(&buf->data[idx], 0, size);

    return ret;
}


static int WOLFCRYPT_BIO_mem_write(WOLFCRYPT_BIO *bio,
                                   const char *buf, int size);
static int WOLFCRYPT_BIO_mem_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int WOLFCRYPT_BIO_mem_puts(WOLFCRYPT_BIO *bio, const char *str);
static int WOLFCRYPT_BIO_mem_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long WOLFCRYPT_BIO_mem_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                  long num, void *ptr);
static int WOLFCRYPT_BIO_mem_new(WOLFCRYPT_BIO *bio);
static int WOLFCRYPT_BIO_mem_free(WOLFCRYPT_BIO *bio);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_mem_method = {
    BIO_TYPE_MEM,
    "Memory buffer",
    WOLFCRYPT_BIO_mem_write,
    WOLFCRYPT_BIO_mem_read,
    WOLFCRYPT_BIO_mem_puts,
    WOLFCRYPT_BIO_mem_gets,
    WOLFCRYPT_BIO_mem_ctrl,
    WOLFCRYPT_BIO_mem_new,
    WOLFCRYPT_BIO_mem_free,
    NULL,
};

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new_mem_buf(void *data, int len)
{
    WOLFCRYPT_BIO       *bio;
    size_t              size;

    if (data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    size = (len < 0) ? strlen((char *)data) : (size_t)len;

    bio = WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_s_mem());
    if (bio == NULL)
        return NULL;

    ((WOLFCRYPT_BUF_MEM *)bio->ptr)->data = (byte*)data;
    ((WOLFCRYPT_BUF_MEM *)bio->ptr)->length = (word32)size;

    bio->flags |= BIO_FLAGS_MEM_RDONLY;
    bio->num = 0;

    return bio;
}

WOLFCRYPT_BIO_METHOD *WOLFCRYPT_BIO_s_mem(void)
{
    return (&WOLFCRYPT_BIO_mem_method);
}

static int WOLFCRYPT_BIO_mem_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->ptr = WOLFCRYPT_BUF_MEM_new();
    if (bio->ptr == NULL)
        return -1;

    bio->shutdown = 1;
    bio->init = 1;
    bio->num = -1;

    return 1;
}

static int WOLFCRYPT_BIO_mem_free(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL)
        return -1;

    if (!bio->shutdown || !bio->init)
        return 1;

    if (bio->ptr != NULL) {
        if (bio->flags & BIO_FLAGS_MEM_RDONLY)
            ((WOLFCRYPT_BUF_MEM *)bio->ptr)->data = NULL;

        WOLFCRYPT_BUF_MEM_free(bio->ptr);
        bio->ptr = NULL;
    }

    bio->init = 0;
    return 1;
}

static int WOLFCRYPT_BIO_mem_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = -1;
    WOLFCRYPT_BUF_MEM *wbmptr;

    if (bio == NULL || !bio->init || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    wbmptr = (WOLFCRYPT_BUF_MEM *)bio->ptr;

    ret = (size >= 0 && (size_t)size > wbmptr->length) ?
            (int)wbmptr->length : size;

    if (data != NULL && ret > 0) {
        XMEMCPY(data, wbmptr->data, ret);
        wbmptr->length -= ret;
        if (bio->flags & BIO_FLAGS_MEM_RDONLY)
            wbmptr->data += ret;
        else
            XMEMMOVE(&(wbmptr->data[0]), &(wbmptr->data[ret]), wbmptr->length);
    }
    else if (wbmptr->length == 0) {
        ret = bio->num;
        if (ret != 0)
            WOLFCRYPT_BIO_set_retry_read(bio);
    }

    return ret;
}

static int WOLFCRYPT_BIO_mem_write(WOLFCRYPT_BIO *bio,
                                   const char *data, int size)
{
    int init_len;
    WOLFCRYPT_BUF_MEM *wbmptr;

    if (bio == NULL || !bio->init || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    if (bio->flags & BIO_FLAGS_MEM_RDONLY) {
        WOLFSSL_ERROR(BIO_MEM_WRITE_E);
        return -1;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    wbmptr = (WOLFCRYPT_BUF_MEM *)bio->ptr;
    init_len = wbmptr->length;

    if (WOLFCRYPT_BUF_MEM_grow_clean(wbmptr, wbmptr->length + size) !=
        (int)(init_len + size))
        return -1;

    XMEMCPY(&(wbmptr->data[init_len]), data, size);

    return size;
}

static long WOLFCRYPT_BIO_mem_ctrl(WOLFCRYPT_BIO *bio,
                                  int cmd, long num, void *ptr)
{
    WOLFCRYPT_BUF_MEM *wbmptr;
    long ret = 1;

    if (bio == NULL || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    wbmptr = (WOLFCRYPT_BUF_MEM *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            if (wbmptr->data == NULL)
                break;

            /* For read only case reset to the start again */
            if (bio->flags & BIO_FLAGS_MEM_RDONLY)
                wbmptr->data -= wbmptr->length;
            else {
                XMEMSET(wbmptr->data, 0, wbmptr->length);
                wbmptr->length = 0;
            }
            break;

        case BIO_CTRL_EOF:
            ret = (long)(wbmptr->length == 0);
            break;

        case BIO_C_SET_BUF_MEM_EOF_RETURN:
            bio->num = (int)num;
            break;

        case BIO_CTRL_INFO:
            ret = (long)wbmptr->length;
            if (ptr != NULL)
                *((char **)ptr) = (char *)&(wbmptr->data[0]);
            break;

        case BIO_C_SET_BUF_MEM:
            WOLFCRYPT_BIO_mem_free(bio);
            bio->shutdown = (int)num;
            bio->ptr = ptr;
            break;

        case BIO_C_GET_BUF_MEM_PTR:
            if (ptr != NULL)
                *((char **)ptr) = (char *)wbmptr;
            break;

        case BIO_CTRL_GET_CLOSE:
            ret = (long)bio->shutdown;
            break;

        case BIO_CTRL_SET_CLOSE:
            bio->shutdown = (int)num;
            break;

        case BIO_CTRL_WPENDING:
            ret = 0;
            break;

        case BIO_CTRL_PENDING:
            ret = (long)wbmptr->length;
            break;

        case BIO_CTRL_DUP:
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;
            
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
            ret = 0;
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

static int WOLFCRYPT_BIO_mem_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    WOLFCRYPT_BUF_MEM *wbmptr;
    int i, blen;

    if (bio == NULL || bio->ptr == NULL || buf == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    WOLFCRYPT_BIO_clear_retry_flags(bio);

    wbmptr = (WOLFCRYPT_BUF_MEM *)bio->ptr;

    if ((int)wbmptr->length > (size - 1))
        blen = size - 1;
    else if (wbmptr->length <= 0) {
        *buf = '\0';
        return 0;
    }
    else
        blen = wbmptr->length;

    for (i = 0; i < blen; i++) {
        if (wbmptr->data[i] == '\n') {
            i++;
            break;
        }
    }

    i = WOLFCRYPT_BIO_mem_read(bio, buf, i);
    if (i > 0)
        buf[i] = '\0';

    return i;
}

static int WOLFCRYPT_BIO_mem_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    return WOLFCRYPT_BIO_mem_write(bio, str, (int)strlen(str));
}

#endif /* OPENSSL_EXTRA */
