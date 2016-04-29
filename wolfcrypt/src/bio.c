/* bio.c
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

#include <stdarg.h>
#include <stdio.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/openssl/bio.h>

WOLFCRYPT_BIO *WOLFCRYPT_BIO_new(WOLFCRYPT_BIO_METHOD *method)
{
    WOLFCRYPT_BIO *bio;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_new");

    if (method == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    bio = (WOLFCRYPT_BIO *)XMALLOC(sizeof(WOLFCRYPT_BIO),
                                   0, DYNAMIC_TYPE_OPENSSL);
    if (bio == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return NULL;
    }

    if (!WOLFCRYPT_BIO_set(bio, method)) {
        XFREE(bio, 0, DYNAMIC_TYPE_OPENSSL);
        return  NULL;
    }

    if (InitMutex(&bio->refMutex) < 0) {
        WOLFSSL_MSG("Mutex error on BIO init");
        return NULL;
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_new", 1);

    return bio;
}

int WOLFCRYPT_BIO_set(WOLFCRYPT_BIO *bio, WOLFCRYPT_BIO_METHOD *method)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_set");

    if (bio == NULL || method == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_set", 0);
        return 0;
    }

    bio->method = method;
    bio->callback = NULL;
    bio->cb_arg = NULL;
    bio->init = 0;
    bio->shutdown = 1;
    bio->flags = 0;
    bio->retry_reason = 0;
    bio->num = 0;
    bio->ptr = NULL;
    bio->prev_bio = NULL;
    bio->next_bio = NULL;
    bio->references = 1;
    bio->num_read = 0;
    bio->num_write = 0;

    if (method->create != NULL)
        if (!method->create(bio)) {
            WOLFSSL_ERROR(BIO_CREATE_METHOD_E);
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_set", 0);
            return 0;
        }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_set", 1);

    return 1;
}

int WOLFCRYPT_BIO_free(WOLFCRYPT_BIO *bio)
{
    long ret;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_free", 0);
        return 0;
    }

    if (LockMutex(&bio->refMutex) != 0) {
        WOLFSSL_MSG("Couldn't lock bio mutex");
        return 0;
    }
    bio->references--;
    if (bio->references > 0) {
        UnLockMutex(&bio->refMutex);
        return 1;
    }
    else if (bio->references < 0) {
        WOLFSSL_ERROR(BIO_BAD_REF);
        WOLFSSL_MSG("WOLFCRYPT_BIO_free bad bio references");
        UnLockMutex(&bio->refMutex);
        return 0;
    }
    UnLockMutex(&bio->refMutex);

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_FREE, NULL, 0, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_free", (int)ret);
            return (int)(ret);
        }
    }

    if (bio->method != NULL && bio->method->destroy != NULL)
        bio->method->destroy(bio);

    /* free refMutex */
    FreeMutex(&bio->refMutex);

    /* free bio */
    XFREE(bio, 0, DYNAMIC_TYPE_OPENSSL);
    bio = NULL;

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_free", 1);
    return 1;
}

void WOLFCRYPT_BIO_clear_flags(WOLFCRYPT_BIO *bio, int flags)
{
    bio->flags &= ~flags;
}

void WOLFCRYPT_BIO_set_flags(WOLFCRYPT_BIO *bio, int flags)
{
    bio->flags |= flags;
}

int WOLFCRYPT_BIO_test_flags(const WOLFCRYPT_BIO *bio, int flags)
{
    return (bio->flags & flags);
}

long (*WOLFCRYPT_BIO_get_callback(const WOLFCRYPT_BIO *bio))
        (WOLFCRYPT_BIO *, int, const char *, int, long, long)
{
    return bio->callback;
}

void WOLFCRYPT_BIO_set_callback(WOLFCRYPT_BIO *bio,
                              long (*cb) (WOLFCRYPT_BIO *, int, const char *,
                                          int, long, long))
{
    bio->callback = cb;
}

void WOLFCRYPT_BIO_set_callback_arg(WOLFCRYPT_BIO *bio, char *arg)
{
    bio->cb_arg = arg;
}

char *WOLFCRYPT_BIO_get_callback_arg(const WOLFCRYPT_BIO *bio)
{
    return bio->cb_arg;
}

const char *WOLFCRYPT_BIO_method_name(const WOLFCRYPT_BIO *bio)
{
    return bio->method->name;
}

int WOLFCRYPT_BIO_method_type(const WOLFCRYPT_BIO *bio)
{
    return bio->method->type;
}

int WOLFCRYPT_BIO_read(WOLFCRYPT_BIO *bio, void *data, int size)
{
    long ret;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_read");

    if ((bio == NULL) || (bio->method == NULL) ||
        (bio->method->bread == NULL) || (data == NULL)) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_read", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_READ, data, size, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_read", (int)ret);
            return (int)(ret);
        }
    }

    if (!bio->init) {
        WOLFSSL_ERROR(BIO_UNINITIALIZED_E);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_read", -2);
        return -2;
    }

    ret = bio->method->bread(bio, data, size);
    if (ret > 0)
        bio->num_read += (unsigned long)ret;

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_READ | BIO_CB_RETURN,
                            data, size, 0, ret);
        if (ret <= 0)
            WOLFSSL_ERROR(BIO_CALLBACK_E);
    }
    
    WOLFSSL_LEAVE("WOLFCRYPT_BIO_read", (int)ret);

    return (int)ret;
}

int WOLFCRYPT_BIO_write(WOLFCRYPT_BIO *bio, const void *data, int size)
{
    long ret;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_write");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_write", 0);
        return 0;
    }

    if ((bio->method == NULL) || (bio->method->bwrite == NULL) || (data == NULL))
    {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_write", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_WRITE, data, size, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_write", (int)ret);
            return (int)(ret);
        }
    }

    if (!bio->init) {
        WOLFSSL_ERROR(BIO_UNINITIALIZED_E);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_write", -2);
        return -2;
    }

    ret = bio->method->bwrite(bio, data, size);
    if (ret > 0)
        bio->num_write += (unsigned long)ret;

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_WRITE | BIO_CB_RETURN,
                            data, size, 0, ret);
        if (ret <= 0)
            WOLFSSL_ERROR(BIO_CALLBACK_E);
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_write", (int)ret);

    return (int)ret;
}

int WOLFCRYPT_BIO_puts(WOLFCRYPT_BIO *bio, const char *data)
{
    long ret;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_puts");

    if ((bio == NULL) || (bio->method == NULL) ||
        (bio->method->bputs == NULL) || (data == NULL)) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_puts", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_PUTS, data, 0, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_puts", (int)ret);
            return (int)(ret);
        }
    }

    if (!bio->init) {
        WOLFSSL_ERROR(BIO_UNINITIALIZED_E);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_puts", -2);
        return -2;
    }

    ret = bio->method->bputs(bio, data);
    if (ret > 0)
        bio->num_write += (unsigned long)ret;

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_PUTS | BIO_CB_RETURN,
                            data, 0, 0, ret);
        if (ret <= 0)
            WOLFSSL_ERROR(BIO_CALLBACK_E);
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_puts", (int)ret);

    return (int)ret;
}

int WOLFCRYPT_BIO_gets(WOLFCRYPT_BIO *bio, char *data, int size)
{
    long ret;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_gets");

    if ((bio == NULL) || (bio->method == NULL) ||
        (bio->method->bgets == NULL) || (data == NULL)) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_gets", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_GETS, data, size, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_gets", (int)ret);
            return (int)(ret);
        }
    }


    if (!bio->init) {
        WOLFSSL_ERROR(BIO_UNINITIALIZED_E);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_gets", -2);
        return -2;
    }

    ret = bio->method->bgets(bio, data, size);

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_GETS | BIO_CB_RETURN,
                            data, size, 0, ret);
        if (ret <= 0)
            WOLFSSL_ERROR(BIO_CALLBACK_E);
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_gets", (int)ret);

    return (int)ret;
}

long WOLFCRYPT_BIO_ctrl(WOLFCRYPT_BIO *bio, int cmd, long larg, void *parg)
{
    long ret;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_ctrl");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_ctrl bio", 0);
        return 0;
    }

    if ((bio->method == NULL) || (bio->method->ctrl == NULL)) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_ctrl method method-ctrl", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_CTRL, parg, cmd, larg, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_ctrl callback", (int)ret);
            return ret;
        }
    }

    ret = bio->method->ctrl(bio, cmd, larg, parg);

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_CTRL | BIO_CB_RETURN,
                             parg, cmd, larg, ret);
        if (ret <= 0)
            WOLFSSL_ERROR(BIO_CALLBACK_E);
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_ctrl", (int)ret);
    return ret;
}

long WOLFCRYPT_BIO_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                               void (*fp) (WOLFCRYPT_BIO *, int, const char *,
                                           int, long, long))
{
    long ret;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_callback_ctrl");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_callback_ctrl", 0);
        return 0;
    }

    if ((bio->method == NULL) || (bio->method->callback_ctrl == NULL)) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_callback_ctrl", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_CTRL, (void *)&fp, cmd, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_callback_ctrl", (int)ret);
            return ret;
        }
    }

    ret = bio->method->callback_ctrl(bio, cmd, fp);

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_CTRL | BIO_CB_RETURN,
                             (void *)&fp, cmd, 0, ret);
        if (ret <= 0)
            WOLFSSL_ERROR(BIO_CALLBACK_E);
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_callback_ctrl", (int)ret);
    return ret;
}


int WOLFCRYPT_BIO_indent(WOLFCRYPT_BIO *bio, int indent, int max)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_indent");

    if (indent < 0)
        indent = 0;
    if (indent > max)
        indent = max;
    while (indent--)
        if (WOLFCRYPT_BIO_puts(bio, " ") != 1) {
            WOLFSSL_ERROR(BIO_PUTS_E);
            WOLFSSL_LEAVE("WOLFCRYPT_BIO_indent", 0);
            return 0;
        }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_indent", 1);
    return 1;
}

long WOLFCRYPT_BIO_int_ctrl(WOLFCRYPT_BIO *bio, int cmd, long larg, int iarg)
{
    int i = iarg;

    return WOLFCRYPT_BIO_ctrl(bio, cmd, larg, (char *)&i);
}

char *WOLFCRYPT_BIO_ptr_ctrl(WOLFCRYPT_BIO *bio, int cmd, long larg)
{
    char *p = NULL;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_ptr_ctrl");

    if (WOLFCRYPT_BIO_ctrl(bio, cmd, larg, (char *)&p) <= 0) {
        WOLFSSL_ERROR(BIO_CTRL_E);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_ptr_ctrl", 0);
        return NULL;
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_ptr_ctrl", 1);

    return p;
}

size_t WOLFCRYPT_BIO_ctrl_pending(WOLFCRYPT_BIO *bio)
{
    return WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_PENDING, 0, NULL);
}

size_t WOLFCRYPT_BIO_ctrl_wpending(WOLFCRYPT_BIO *bio)
{
    return WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, NULL);
}

/* put the 'bio' on the end of b's list of operators */
WOLFCRYPT_BIO *WOLFCRYPT_BIO_push(WOLFCRYPT_BIO *top, WOLFCRYPT_BIO *next)
{
    WOLFCRYPT_BIO *tmp;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_push");

    if (top == NULL) {
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_push", 0);
        return next;
    }

    tmp = top;
    while (tmp->next_bio != NULL)
        tmp = tmp->next_bio;
    tmp->next_bio = next;
    if (next != NULL)
        next->prev_bio = tmp;

    /* called to do internal processing */
    WOLFCRYPT_BIO_ctrl(top, BIO_CTRL_PUSH, 0, tmp);

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_push", 1);

    return top;
}

/* Remove the first and return the rest */
WOLFCRYPT_BIO *WOLFCRYPT_BIO_pop(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO *ret;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_pop");

    if (bio == NULL)
        return NULL;

    ret = bio->next_bio;

    WOLFCRYPT_BIO_ctrl(bio, BIO_CTRL_POP, 0, bio);

    if (bio->prev_bio != NULL)
        bio->prev_bio->next_bio = bio->next_bio;
    if (bio->next_bio != NULL)
        bio->next_bio->prev_bio = bio->prev_bio;

    bio->next_bio = NULL;
    bio->prev_bio = NULL;

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_pop", 1);

    return ret;
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_get_retry_BIO(WOLFCRYPT_BIO *bio, int *reason)
{
    WOLFCRYPT_BIO *b, *last;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_get_retry_BIO");

    b = last = bio;
    for (; b != NULL; ) {
        if (!WOLFCRYPT_BIO_should_retry(b))
            break;
        last = b;
        b = b->next_bio;
    }

    if (reason != NULL)
        *reason = last->retry_reason;

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_get_retry_BIO", 1);

    return last;
}

int WOLFCRYPT_BIO_get_retry_reason(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_get_retry_reason");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_get_retry_reason", -1);
        return -1;
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_get_retry_reason", (int)bio->retry_reason);

    return bio->retry_reason;
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_find_type(WOLFCRYPT_BIO *bio, int type)
{
    int mt, mask;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_find_type");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_find_type", -1);
        return NULL;
    }

    mask = type & 0xff;
    do {
        if (bio->method != NULL) {
            mt = bio->method->type;

            if (!mask) {
                if (mt & type) {
                    WOLFSSL_LEAVE("WOLFCRYPT_BIO_find_type", type);
                    return bio;
                }
            }
            else if (mt == type) {
                WOLFSSL_LEAVE("WOLFCRYPT_BIO_find_type", type);
                return bio;
            }
        }
        bio = bio->next_bio;
    } while (bio != NULL);

    WOLFSSL_ERROR(BIO_FIND_TYPE_E);
    return NULL;
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_next(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_next");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_next", 0);
        return NULL;
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_next", 1);

    return bio->next_bio;
}

void WOLFCRYPT_BIO_free_all(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO *b;
    int ref;

    WOLFSSL_ENTER("WOLFCRYPT_BIO_free_all");

    while (bio != NULL) {
        b = bio;
        ref = b->references;
        bio = bio->next_bio;
        WOLFCRYPT_BIO_free(b);

        if (ref > 1)
            break;
    }

    WOLFSSL_LEAVE("WOLFCRYPT_BIO_free_all", 1);
}

unsigned long WOLFCRYPT_BIO_number_read(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("BIO_number_read");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_number_read", 0);
        return 0;
    }

    WOLFSSL_LEAVE("BIO_number_read", (int)bio->num_read);

    return bio->num_read;
}

unsigned long WOLFCRYPT_BIO_number_written(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("BIO_number_written");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("WOLFCRYPT_BIO_number_written", 0);
        return 0;
    }

    WOLFSSL_LEAVE("BIO_number_written", (int)bio->num_write);

    return bio->num_write;
}


__attribute__((format(printf, 2, 3)))
int WOLFCRYPT_BIO_printf(WOLFCRYPT_BIO *bio, const char *format, ...)
{
    int     size, ret;
    va_list args, args2;
    char    *buffer = NULL;

    va_start(args, format);

    /* save a copy of va_list to be able to parse 2 times */
    va_copy(args2, args);

    /* compute the required size for buffer */
#if defined(USE_WINDOWS_API)
    size = _vscprintf(format, args);
#else
    size = vsnprintf(NULL, 0, format, args);
#endif
    va_end(args);

    if (size <= 0)
        return -1;

    buffer = (char *)XMALLOC(size+1, 0, DYNAMIC_TYPE_OPENSSL);
    if (buffer == NULL)
        return -1;

    XMEMSET(buffer, 0, size+1);

    ret = vsnprintf(buffer, size+1, format, args2);
    va_end(args2);

    if (ret != size) {
        XFREE(buffer, 0, DYNAMIC_TYPE_OPENSSL);
        return -1;
    }

    ret = WOLFCRYPT_BIO_write(bio, buffer, size);

    XFREE(buffer, 0, DYNAMIC_TYPE_OPENSSL);
    return ret;
}

void WOLFCRYPT_BIO_copy_next_retry(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_set_flags(bio, WOLFCRYPT_BIO_get_retry_flags(bio->next_bio));
    bio->retry_reason = bio->next_bio->retry_reason;
}

WOLFCRYPT_BIO *WOLFCRYPT_BIO_dup_chain(WOLFCRYPT_BIO *in)
{
    WOLFCRYPT_BIO *ret = NULL, *eoc = NULL, *bio, *new_bio;

    for (bio = in; bio != NULL; bio = bio->next_bio) {
        new_bio = WOLFCRYPT_BIO_new(bio->method);
        if (new_bio == NULL) {
            goto err;
        }
        new_bio->callback = bio->callback;
        new_bio->cb_arg = bio->cb_arg;
        new_bio->init = bio->init;
        new_bio->shutdown = bio->shutdown;
        new_bio->flags = bio->flags;
        new_bio->num = bio->num;

        if (!WOLFCRYPT_BIO_dup_state(bio, new_bio)) {
            WOLFCRYPT_BIO_free(new_bio);
            goto err;
        }

        if (ret == NULL) {
            eoc = new_bio;
            ret = eoc;
        } else {
            WOLFCRYPT_BIO_push(eoc, new_bio);
            eoc = new_bio;
        }
    }

    return ret;

err:
    WOLFCRYPT_BIO_free_all(ret);
    return NULL;

}

#endif /* OPENSSL_EXTRA */
