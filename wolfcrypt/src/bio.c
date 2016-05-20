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
#ifndef NO_STDIO_FILESYSTEM
#include <stdio.h>
#endif

#include <sys/types.h>
#include <errno.h>

#ifdef USE_WINDOWS_API
#include <winsock2.h>
#include <process.h>
#include <io.h>
#include <fcntl.h>
#define SHUT_RDWR SD_BOTH
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <fcntl.h>
#include <netdb.h>
#ifndef SO_NOSIGPIPE
#include <signal.h>
#endif
#endif /* USE_WINDOWS_API */


#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>
#endif


#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/bio.h>

static int wc_BioIntToStr(int i, char *str, int strSz){
    char const digit[] = "0123456789";
    int shift, count = 0;

    if (i < 0)
        return -1;

    shift = i;

    do {
        ++str;
        shift = shift/10;
        count++;
    } while(shift);

    /* check size */
    if (strSz <= count)
        return -1;

    *str = '\0';

    do {
        *--str = digit[i%10];
        i = i/10;
    } while(i);

    return count;
}

WOLFCRYPT_BIO *wc_BioNew(WOLFCRYPT_BIO_METHOD *method)
{
    WOLFCRYPT_BIO *bio;

    WOLFSSL_ENTER("wc_BioNew");

    if (method == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    bio = (WOLFCRYPT_BIO *)XMALLOC(sizeof(WOLFCRYPT_BIO),0,DYNAMIC_TYPE_OPENSSL);
    if (bio == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return NULL;
    }

    if (!wc_BioSet(bio, method)) {
        XFREE(bio, 0, DYNAMIC_TYPE_OPENSSL);
        return  NULL;
    }

    if (InitMutex(&bio->refMutex) < 0) {
        WOLFSSL_MSG("Mutex error on BIO init");
        return NULL;
    }

    WOLFSSL_LEAVE("wc_BioNew", 1);

    return bio;
}

int wc_BioSet(WOLFCRYPT_BIO *bio, WOLFCRYPT_BIO_METHOD *method)
{
    WOLFSSL_ENTER("wc_BioSet");

    if (bio == NULL || method == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioSet", 0);
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
            WOLFSSL_LEAVE("wc_BioSet", 0);
            return 0;
        }

    WOLFSSL_LEAVE("wc_BioSet", 1);

    return 1;
}

int wc_BioFree(WOLFCRYPT_BIO *bio)
{
    long ret;

    WOLFSSL_ENTER("wc_BioFree");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioFree", 0);
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
        WOLFSSL_MSG("wc_BioFree bad bio references");
        UnLockMutex(&bio->refMutex);
        return 0;
    }
    UnLockMutex(&bio->refMutex);

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_FREE, NULL, 0, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("wc_BioFree", (int)ret);
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

    WOLFSSL_LEAVE("wc_BioFree", 1);
    return 1;
}

void wc_BioClearFlags(WOLFCRYPT_BIO *bio, int flags)
{
    bio->flags &= ~flags;
}

void wc_BioSetFlags(WOLFCRYPT_BIO *bio, int flags)
{
    bio->flags |= flags;
}

int wc_BioTestFlags(const WOLFCRYPT_BIO *bio, int flags)
{
    return (bio->flags & flags);
}

long (*wc_BioGetCallback(const WOLFCRYPT_BIO *bio))
        (WOLFCRYPT_BIO *, int, const char *, int, long, long)
{
    return bio->callback;
}

void wc_BioSetCallback(WOLFCRYPT_BIO *bio,
                       long (*cb) (WOLFCRYPT_BIO *, int, const char *,
                                   int, long, long))
{
    bio->callback = cb;
}

void wc_BioSetCallbackArg(WOLFCRYPT_BIO *bio, char *arg)
{
    bio->cb_arg = arg;
}

char *wc_BioGetCallbackArg(const WOLFCRYPT_BIO *bio)
{
    return bio->cb_arg;
}

const char *wc_BioMethodName(const WOLFCRYPT_BIO *bio)
{
    return bio->method->name;
}

int wc_BioMethodType(const WOLFCRYPT_BIO *bio)
{
    return bio->method->type;
}

int wc_BioRead(WOLFCRYPT_BIO *bio, void *data, int size)
{
    long ret;

    WOLFSSL_ENTER("wc_BioRead");

    if ((bio == NULL) || (bio->method == NULL) ||
        (bio->method->bread == NULL) || (data == NULL)) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioRead", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_READ, data, size, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("wc_BioRead", (int)ret);
            return (int)(ret);
        }
    }

    if (!bio->init) {
        WOLFSSL_ERROR(BIO_UNINITIALIZED_E);
        WOLFSSL_LEAVE("wc_BioRead", -2);
        return -2;
    }

    ret = bio->method->bread(bio, data, size);
    if (ret > 0)
        bio->num_read += (unsigned long)ret;

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_READ | BIO_CB_RETURN,
                            data, size, 0, ret);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
        }
    }
    
    WOLFSSL_LEAVE("wc_BioRead", (int)ret);

    return (int)ret;
}

int wc_BioWrite(WOLFCRYPT_BIO *bio, const void *data, int size)
{
    long ret;

    WOLFSSL_ENTER("wc_BioWrite");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioWrite", 0);
        return 0;
    }

    if ((bio->method == NULL) || (bio->method->bwrite == NULL) || (data == NULL))
    {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioWrite", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_WRITE, data, size, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("wc_BioWrite", (int)ret);
            return (int)(ret);
        }
    }

    if (!bio->init) {
        WOLFSSL_ERROR(BIO_UNINITIALIZED_E);
        WOLFSSL_LEAVE("wc_BioWrite", -2);
        return -2;
    }

    ret = bio->method->bwrite(bio, data, size);
    if (ret > 0)
        bio->num_write += (unsigned long)ret;

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_WRITE | BIO_CB_RETURN,
                            data, size, 0, ret);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
        }
    }

    WOLFSSL_LEAVE("wc_BioWrite", (int)ret);

    return (int)ret;
}

int wc_BioPuts(WOLFCRYPT_BIO *bio, const char *data)
{
    long ret;

    WOLFSSL_ENTER("wc_BioPuts");

    if ((bio == NULL) || (bio->method == NULL) ||
        (bio->method->bputs == NULL) || (data == NULL)) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioPuts", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_PUTS, data, 0, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("wc_BioPuts", (int)ret);
            return (int)(ret);
        }
    }

    if (!bio->init) {
        WOLFSSL_ERROR(BIO_UNINITIALIZED_E);
        WOLFSSL_LEAVE("wc_BioPuts", -2);
        return -2;
    }

    ret = bio->method->bputs(bio, data);
    if (ret > 0)
        bio->num_write += (unsigned long)ret;

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_PUTS | BIO_CB_RETURN,
                            data, 0, 0, ret);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
        }
    }

    WOLFSSL_LEAVE("wc_BioPuts", (int)ret);

    return (int)ret;
}

int wc_BioGets(WOLFCRYPT_BIO *bio, char *data, int size)
{
    long ret;

    WOLFSSL_ENTER("wc_BioGets");

    if ((bio == NULL) || (bio->method == NULL) ||
        (bio->method->bgets == NULL) || (data == NULL)) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioGets", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_GETS, data, size, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("wc_BioGets", (int)ret);
            return (int)(ret);
        }
    }


    if (!bio->init) {
        WOLFSSL_ERROR(BIO_UNINITIALIZED_E);
        WOLFSSL_LEAVE("wc_BioGets", -2);
        return -2;
    }

    ret = bio->method->bgets(bio, data, size);

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_GETS | BIO_CB_RETURN,
                            data, size, 0, ret);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
        }
    }

    WOLFSSL_LEAVE("wc_BioGets", (int)ret);

    return (int)ret;
}

long wc_BioCtrl(WOLFCRYPT_BIO *bio, int cmd, long larg, void *parg)
{
    long ret;

    WOLFSSL_ENTER("wc_BioCtrl");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioCtrl bio", 0);
        return 0;
    }

    if ((bio->method == NULL) || (bio->method->ctrl == NULL)) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioCtrl method method-ctrl", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_CTRL, parg, cmd, larg, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("wc_BioCtrl callback", (int)ret);
            return ret;
        }
    }

    ret = bio->method->ctrl(bio, cmd, larg, parg);

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_CTRL | BIO_CB_RETURN,
                            parg, cmd, larg, ret);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
        }
    }

    WOLFSSL_LEAVE("wc_BioCtrl", (int)ret);
    return ret;
}

long wc_BioCallbackCtrl(WOLFCRYPT_BIO *bio, int cmd,
                        void (*fp) (WOLFCRYPT_BIO *, int, const char *,
                                    int, long, long))
{
    long ret;

    WOLFSSL_ENTER("wc_BioCallbackCtrl");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioCallbackCtrl", 0);
        return 0;
    }

    if ((bio->method == NULL) || (bio->method->callback_ctrl == NULL)) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioCallbackCtrl", -2);
        return -2;
    }

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_CTRL, (void *)&fp, cmd, 0, 1);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            WOLFSSL_LEAVE("wc_BioCallbackCtrl", (int)ret);
            return ret;
        }
    }

    ret = bio->method->callback_ctrl(bio, cmd, fp);

    /* callback if set */
    if (bio->callback != NULL) {
        ret = bio->callback(bio, BIO_CB_CTRL | BIO_CB_RETURN,
                             (void *)&fp, cmd, 0, ret);
        if (ret <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
        }
    }

    WOLFSSL_LEAVE("wc_BioCallbackCtrl", (int)ret);
    return ret;
}


int wc_BioIndent(WOLFCRYPT_BIO *bio, int indent, int max)
{
    WOLFSSL_ENTER("wc_BioIndent");

    if (indent < 0)
        indent = 0;
    if (indent > max)
        indent = max;
    while (indent--)
        if (wc_BioPuts(bio, " ") != 1) {
            WOLFSSL_ERROR(BIO_PUTS_E);
            WOLFSSL_LEAVE("wc_BioIndent", 0);
            return 0;
        }

    WOLFSSL_LEAVE("wc_BioIndent", 1);
    return 1;
}

long wc_BioIntCtrl(WOLFCRYPT_BIO *bio, int cmd, long larg, int iarg)
{
    int i = iarg;

    return wc_BioCtrl(bio, cmd, larg, (char *)&i);
}

char *wc_BioPtrCtrl(WOLFCRYPT_BIO *bio, int cmd, long larg)
{
    char *p = NULL;

    WOLFSSL_ENTER("wc_BioPtrCtrl");

    if (wc_BioCtrl(bio, cmd, larg, (char *)&p) <= 0) {
        WOLFSSL_ERROR(BIO_CTRL_E);
        WOLFSSL_LEAVE("wc_BioPtrCtrl", 0);
        return NULL;
    }

    WOLFSSL_LEAVE("wc_BioPtrCtrl", 1);

    return p;
}

size_t wc_BioCtrlPending(WOLFCRYPT_BIO *bio)
{
    return wc_BioCtrl(bio, BIO_CTRL_PENDING, 0, NULL);
}

size_t wc_BioCtrlWpending(WOLFCRYPT_BIO *bio)
{
    return wc_BioCtrl(bio, BIO_CTRL_WPENDING, 0, NULL);
}

/* put the 'bio' on the end of b's list of operators */
WOLFCRYPT_BIO *wc_BioPush(WOLFCRYPT_BIO *top, WOLFCRYPT_BIO *next)
{
    WOLFCRYPT_BIO *tmp;

    WOLFSSL_ENTER("wc_BioPush");

    if (top == NULL) {
        WOLFSSL_LEAVE("wc_BioPush", 0);
        return next;
    }

    tmp = top;
    while (tmp->next_bio != NULL)
        tmp = tmp->next_bio;
    tmp->next_bio = next;
    if (next != NULL)
        next->prev_bio = tmp;

    /* called to do internal processing */
    wc_BioCtrl(top, BIO_CTRL_PUSH, 0, tmp);

    WOLFSSL_LEAVE("wc_BioPush", 1);

    return top;
}

/* Remove the first and return the rest */
WOLFCRYPT_BIO *wc_BioPop(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO *ret;

    WOLFSSL_ENTER("wc_BioPop");

    if (bio == NULL)
        return NULL;

    ret = bio->next_bio;

    wc_BioCtrl(bio, BIO_CTRL_POP, 0, bio);

    if (bio->prev_bio != NULL)
        bio->prev_bio->next_bio = bio->next_bio;
    if (bio->next_bio != NULL)
        bio->next_bio->prev_bio = bio->prev_bio;

    bio->next_bio = NULL;
    bio->prev_bio = NULL;

    WOLFSSL_LEAVE("wc_BioPop", 1);

    return ret;
}

WOLFCRYPT_BIO *wc_BioGetRetryBio(WOLFCRYPT_BIO *bio, int *reason)
{
    WOLFCRYPT_BIO *b, *last;

    WOLFSSL_ENTER("wc_BioGetRetryBio");

    b = last = bio;
    for (; b != NULL; ) {
        if (!wc_BioShouldRetry(b))
            break;
        last = b;
        b = b->next_bio;
    }

    if (reason != NULL)
        *reason = last->retry_reason;

    WOLFSSL_LEAVE("wc_BioGetRetryBio", 1);

    return last;
}

int wc_BioGetRetryReason(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioGetRetryReason");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioGetRetryReason", -1);
        return -1;
    }

    WOLFSSL_LEAVE("wc_BioGetRetryReason", (int)bio->retry_reason);

    return bio->retry_reason;
}

WOLFCRYPT_BIO *wc_BioFindType(WOLFCRYPT_BIO *bio, int type)
{
    int mt, mask;

    WOLFSSL_ENTER("wc_BioFindType");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioFindType", -1);
        return NULL;
    }

    mask = type & 0xff;
    do {
        if (bio->method != NULL) {
            mt = bio->method->type;

            if (!mask) {
                if (mt & type) {
                    WOLFSSL_LEAVE("wc_BioFindType", type);
                    return bio;
                }
            }
            else if (mt == type) {
                WOLFSSL_LEAVE("wc_BioFindType", type);
                return bio;
            }
        }
        bio = bio->next_bio;
    } while (bio != NULL);

    WOLFSSL_ERROR(BIO_FIND_TYPE_E);
    return NULL;
}

WOLFCRYPT_BIO *wc_BioNext(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioNext");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioNext", 0);
        return NULL;
    }

    WOLFSSL_LEAVE("wc_BioNext", 1);

    return bio->next_bio;
}

void wc_BioFreeAll(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO *b;
    int ref;

    WOLFSSL_ENTER("wc_BioFreeAll");

    while (bio != NULL) {
        b = bio;
        ref = b->references;
        bio = bio->next_bio;
        wc_BioFree(b);

        if (ref > 1)
            break;
    }

    WOLFSSL_LEAVE("wc_BioFreeAll", 1);
}

unsigned long wc_BioNumberRead(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioNumberRead");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioNumberRead", 0);
        return 0;
    }

    WOLFSSL_LEAVE("wc_BioNumberRead", (int)bio->num_read);

    return bio->num_read;
}

unsigned long wc_BioNumberWritten(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioNumberWritten");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        WOLFSSL_LEAVE("wc_BioNumberWritten", 0);
        return 0;
    }

    WOLFSSL_LEAVE("wc_BioNumberWritten", (int)bio->num_write);

    return bio->num_write;
}


#ifndef NO_STDIO_FILESYSTEM

#ifndef USE_WINDOWS_API
__attribute__((format(printf, 2, 3)))
#endif
int wc_BioPrintf(WOLFCRYPT_BIO *bio, const char *format, ...)
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

    ret = wc_BioWrite(bio, buffer, size);

    XFREE(buffer, 0, DYNAMIC_TYPE_OPENSSL);
    return ret;
}
#endif /* NO_STDIO_FILESYSTEM */

void wc_BioCopyNextRetry(WOLFCRYPT_BIO *bio)
{
    wc_BioSetFlags(bio, wc_BioGetRetryFlags(bio->next_bio));
    bio->retry_reason = bio->next_bio->retry_reason;
}

WOLFCRYPT_BIO *wc_BioDupChain(WOLFCRYPT_BIO *in)
{
    WOLFCRYPT_BIO *ret = NULL, *eoc = NULL, *bio, *new_bio;

    for (bio = in; bio != NULL; bio = bio->next_bio) {
        new_bio = wc_BioNew(bio->method);
        if (new_bio == NULL) {
            goto err;
        }
        new_bio->callback = bio->callback;
        new_bio->cb_arg = bio->cb_arg;
        new_bio->init = bio->init;
        new_bio->shutdown = bio->shutdown;
        new_bio->flags = bio->flags;
        new_bio->num = bio->num;

        if (!wc_BioDupState(bio, new_bio)) {
            wc_BioFree(new_bio);
            goto err;
        }

        if (ret == NULL) {
            eoc = new_bio;
            ret = eoc;
        } else {
            wc_BioPush(eoc, new_bio);
            eoc = new_bio;
        }
    }

    return ret;

err:
    wc_BioFreeAll(ret);
    return NULL;

}

/* start BIO Filter base64 */

static int wc_BioB64_write(WOLFCRYPT_BIO *bio, const char *buf, int size);
static int wc_BioB64_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int wc_BioB64_puts(WOLFCRYPT_BIO *bio, const char *str);
static long wc_BioB64_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioB64_new(WOLFCRYPT_BIO *bio);
static int wc_BioB64_free(WOLFCRYPT_BIO *bio);
static long wc_BioB64_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                    WOLFCRYPT_BIO_info_cb *fp);

#define WOLFCRYPT_B64_BLOCK_SIZE  20*48
#define WOLFCRYPT_B64_ENCODE_SIZE 20*64 + 40 // 40 : 20 CR LF
#define WOLFCRYPT_B64_NONE        0
#define WOLFCRYPT_B64_ENCODE      1
#define WOLFCRYPT_B64_DECODE      2


typedef struct {
    int dataLen; /* data length */
    int dataIdx; /* data index */
    int workLen; /* working buffer length */
    int workNl;  /* used to stop when find a '\n' */
    int encode;  /* base64 operation */
    int start;   /* decoding started */
    int cont;    /* <= 0 when finished */

    char data[WOLFCRYPT_B64_ENCODE_SIZE];
    char work[WOLFCRYPT_B64_BLOCK_SIZE];
} WOLFCRYPT_BIO_F_B64_CTX;

static WOLFCRYPT_BIO_METHOD wc_BioB64_method = {
    BIO_TYPE_BASE64,
    "Base64",
    wc_BioB64_write,
    wc_BioB64_read,
    wc_BioB64_puts,
    NULL,                       /* gets */
    wc_BioB64_ctrl,
    wc_BioB64_new,
    wc_BioB64_free,
    wc_BioB64_callback_ctrl,
};


WOLFCRYPT_BIO_METHOD *wc_Bio_f_base64(void)
{
    return (&wc_BioB64_method);
}

static int wc_BioB64_new(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_F_B64_CTX *ctx;

    WOLFSSL_ENTER("wc_BioB64_new");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio->ptr = (WOLFCRYPT_BIO_F_B64_CTX *)
    XMALLOC(sizeof(WOLFCRYPT_BIO_F_B64_CTX),
            0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_F_B64_CTX *)bio->ptr;

    ctx->dataLen = 0;
    ctx->workLen = 0;
    ctx->workNl = 0;
    ctx->dataIdx = 0;
    ctx->cont = 1;
    ctx->start = 1;
    ctx->encode = 0;

    bio->init = 1;
    bio->flags = 0;
    bio->num = 0;

    WOLFSSL_LEAVE("wc_BioB64_new", 1);
    return 1;
}

static int wc_BioB64_free(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioB64_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (bio->ptr != NULL) {
        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
        bio->ptr = NULL;
    }

    bio->init = 0;
    bio->flags = 0;

    WOLFSSL_LEAVE("wc_BioB64_free", 1);

    return 1;
}


static int wc_BioB64_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 0, idx, bread, j, k, num, ret_code = 0;
    WOLFCRYPT_BIO_F_B64_CTX *ctx;

    WOLFSSL_ENTER("wc_BioB64_read");

    if (bio == NULL || !bio->init || bio->ptr == NULL ||
        bio->next_bio == NULL || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    wc_BioClearRetryFlags(bio);

    ctx = (WOLFCRYPT_BIO_F_B64_CTX *)bio->ptr;

    /* decode when reading */
    if (ctx->encode != WOLFCRYPT_B64_DECODE) {
        ctx->encode = WOLFCRYPT_B64_DECODE;
        ctx->dataLen = 0;
        ctx->dataIdx = 0;
        ctx->workLen = 0;
    }

    /* First check if there are bytes decoded/encoded */
    if (ctx->dataLen > 0) {
        if (ctx->dataLen < ctx->dataIdx) {
            WOLFSSL_LEAVE("wc_BioB64_read", -1);
            return -1;
        }

        bread = ctx->dataLen - ctx->dataIdx;
        if (bread > size)
            bread = size;

        if (ctx->dataIdx + bread >= (int)sizeof(ctx->data)) {
            WOLFSSL_LEAVE("wc_BioB64_read", -1);
            return -1;
        }

        XMEMCPY(data, &(ctx->data[ctx->dataIdx]), bread);

        ret = bread;
        data += bread;
        size -= bread;
        ctx->dataIdx += bread;

        if (ctx->dataLen == ctx->dataIdx) {
            ctx->dataLen = 0;
            ctx->dataIdx = 0;
        }
    }

    /*
     * At this point, we have room of size bytes and an empty buffer, so we
     * should read in some more.
     */

    ret_code = 0;
    idx = 0;

    while (size > 0) {
        if (ctx->cont <= 0)
            break;

        bread = wc_BioRead(bio->next_bio, &ctx->work[ctx->workLen],
                           sizeof(ctx->work) - ctx->workLen);

        if (bread <= 0) {
            ret_code = bread;

            /* Should we continue next time we are called? */
            if (!wc_BioShouldRetry(bio->next_bio)) {
                ctx->cont = bread;
                /* If buffer empty break */
                if (!ctx->workLen)
                    break;
                else
                    bread = 0;
            }
            /* else we retry and add more data to buffer */
            else
                break;
        }

        bread += ctx->workLen;
        ctx->workLen = bread;

        /*
         * We need to scan, a line at a time until we have a valid line if we
         * are starting.
         */
        if (ctx->start && (wc_BioGetFlags(bio) & BIO_FLAGS_BASE64_NO_NL))
            ctx->workLen = 0;
        else if (ctx->start) {
            /* search \n */
            ctx->workNl = -1;

            /* parse working buffer to find line endings */
            for (j = 0; j < bread; j++) {

                /* no end of line, continue */
                if (ctx->work[j] != '\n')
                    continue;

                /* we found an end of line, keep the position to
                 * decode the line */
                ctx->workNl = j;

                /* decode the line found */
                num = sizeof(ctx->data) - ctx->dataIdx;

                k = Base64_Decode((const byte*)ctx->work+idx,ctx->workNl-idx,
                                  (byte *)ctx->data+ctx->dataIdx, (word32 *)&num);
                if (k < 0 && !num && ctx->start) {
                    WOLFSSL_ERROR(BIO_B64_DECODE_E);
                    return -1;
                }
                else
                    ctx->start = 0;

                /* +1 => skeep \n */
                idx = (ctx->workNl + 1);

                ctx->dataLen += num;
                ctx->dataIdx += num;
            }
        } else if ((bread < WOLFCRYPT_B64_BLOCK_SIZE) && (ctx->cont > 0)) {
            /*
             * If buffer isn't full and we can retry then restart to read in
             * more data.
             */
            continue;
        }

        if (wc_BioGetFlags(bio) & BIO_FLAGS_BASE64_NO_NL) {
            int z, jj;

            jj = bread & ~3;

            z = sizeof(ctx->data);
            k = Base64_Decode((const byte*)ctx->work, jj,
                              (byte *)ctx->data, (word32 *)&z);
            if (k < 0 || !z) {
                WOLFSSL_ERROR(BIO_B64_DECODE_E);
                return -1;
            }

            /* z is now number of output bytes and jj is the number consumed
             */
            if (jj != bread) {
                ctx->workLen = bread - jj;
                XMEMMOVE(ctx->work, &ctx->work[jj], ctx->workLen);
            }

            if (z > 0)
                ctx->dataLen = z;
            else
                ctx->dataLen = 0;

            bread = z;
        }

        ctx->dataIdx = 0;
        if (bread < 0) {
            ret_code = 0;
            ctx->dataLen = 0;
            break;
        }

        if (!(wc_BioGetFlags(bio) & BIO_FLAGS_BASE64_NO_NL)) {
            /* keep no parsed data in working buffer */
            XMEMMOVE(ctx->work, ctx->work+idx, ctx->workLen-idx);
            ctx->workLen -= idx;
            idx = 0;
            ctx->start = 1;
        }

        bread = (ctx->dataLen <= size ? ctx->dataLen : size);

        XMEMCPY(data, ctx->data, bread);
        ret += bread;

        if (bread == ctx->dataLen) {
            ctx->dataLen = 0;
            ctx->dataIdx = 0;
        }
        else
            ctx->dataIdx = bread;

        size -= bread;
        data += bread;
    }

    wc_BioCopyNextRetry(bio);

    WOLFSSL_LEAVE("wc_BioB64_read", (!ret ? ret_code : ret));

    return (!ret ? ret_code : ret);
}

static int wc_BioB64_write(WOLFCRYPT_BIO *bio, const char *data, int size)
{
    int ret = 0;
    int n;
    int i;
    WOLFCRYPT_BIO_F_B64_CTX *ctx;

    WOLFSSL_ENTER("wc_BioB64_write");

    if (bio == NULL || !bio->init || bio->ptr == NULL ||
        bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    wc_BioClearRetryFlags(bio);

    ctx = (WOLFCRYPT_BIO_F_B64_CTX *)bio->ptr;

    /* encode when writing */
    if (ctx->encode != WOLFCRYPT_B64_ENCODE) {
        ctx->encode = WOLFCRYPT_B64_ENCODE;
        ctx->dataLen = 0;
        ctx->dataIdx = 0;
        ctx->workLen = 0;
    }

    if (ctx->dataIdx >= (int)sizeof(ctx->data) ||
        ctx->dataLen > (int)sizeof(ctx->data) ||
        ctx->dataLen < ctx->dataIdx) {
        WOLFSSL_LEAVE("wc_BioB64_write", -1);
        return -1;
    }

    n = ctx->dataLen - ctx->dataIdx;
    while (n > 0) {
        i = wc_BioWrite(bio->next_bio, &ctx->data[ctx->dataIdx], n);
        if (i <= 0) {
            wc_BioCopyNextRetry(bio);
            return i;
        }

        /* mustn't appen, just to be sure */
        if (i > n) {
            WOLFSSL_LEAVE("wc_BioB64_write", -1);
            return -1;
        }

        ctx->dataIdx += i;
        n -= i;

        if (ctx->dataIdx > (int)sizeof(ctx->data) ||
            ctx->dataLen < ctx->dataIdx) {
            WOLFSSL_LEAVE("wc_BioB64_write", -1);
            return -1;
        }
    }

    /* at this point all pending data has been written */
    ctx->dataIdx = 0;
    ctx->dataLen = 0;

    if (data == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    while (size > 0) {
        n = (size > WOLFCRYPT_B64_BLOCK_SIZE) ? WOLFCRYPT_B64_BLOCK_SIZE : size;

        if (ctx->workLen > 0) {
            if (ctx->workLen > WOLFCRYPT_B64_BLOCK_SIZE) {
                WOLFSSL_LEAVE("wc_BioB64_write", -1);
                return -1;
            }

            n = WOLFCRYPT_B64_BLOCK_SIZE - ctx->workLen;

            if (n > size)
                n = size;

            XMEMCPY(&ctx->work[ctx->workLen], data, n);
            ctx->workLen += n;
            ret += n;
            if (ctx->workLen < WOLFCRYPT_B64_BLOCK_SIZE)
                break;

            ctx->dataLen = sizeof(ctx->data);

            if (wc_BioGetFlags(bio) & BIO_FLAGS_BASE64_NO_NL)
                Base64_Encode_NoNl((const byte *)ctx->work, ctx->workLen,
                                   (byte *)ctx->data,
                                   (word32 *)&ctx->dataLen);
            else
                Base64_Encode((const byte *)ctx->work, ctx->workLen,
                              (byte *)ctx->data, (word32 *)&ctx->dataLen);

            if (ctx->dataLen > (int)sizeof(ctx->data) ||
                ctx->dataLen < ctx->dataIdx) {
                WOLFSSL_LEAVE("wc_BioB64_write", -1);
                return -1;
            }

            ctx->workLen = 0;
        }
        else {
            /* keep data and wait for more before encoding */
            if (n < WOLFCRYPT_B64_BLOCK_SIZE) {
                XMEMCPY(ctx->work, data, n);
                ctx->workLen = n;
                ret += n;
                break;
            }
            n -= n % WOLFCRYPT_B64_BLOCK_SIZE;

            ctx->dataLen = sizeof(ctx->data);

            if (wc_BioGetFlags(bio) & BIO_FLAGS_BASE64_NO_NL)
                Base64_Encode_NoNl((const byte *)data, n,
                                   (byte *)ctx->data,
                                   (word32 *)&ctx->dataLen);
            else
                Base64_Encode((const byte *)data, n,
                              (byte *)ctx->data, (word32 *)&ctx->dataLen);

            if (ctx->dataLen > (int)sizeof(ctx->data) ||
                ctx->dataLen < ctx->dataIdx) {
                WOLFSSL_LEAVE("wc_BioB64_write", -1);
                return -1;
            }

            ret += n;
        }

        size -= n;
        data += n;

        ctx->dataIdx = 0;
        n = ctx->dataLen;
        while (n > 0) {
            i = wc_BioWrite(bio->next_bio, &(ctx->data[ctx->dataIdx]), n);
            if (i <= 0) {
                wc_BioCopyNextRetry(bio);
                WOLFSSL_LEAVE("wc_BioB64_write", !ret ? i : ret);
                return (!ret ? i : ret);
            }

            if (i > n) {
                WOLFSSL_LEAVE("wc_BioB64_write", -1);
                return -1;
            }

            n -= i;
            ctx->dataIdx += i;

            if (ctx->dataLen > (int)sizeof(ctx->data) ||
                ctx->dataLen < ctx->dataIdx) {
                WOLFSSL_LEAVE("wc_BioB64_write", -1);
                return -1;
            }
        }

        ctx->dataLen = 0;
        ctx->dataIdx = 0;
    }

    WOLFSSL_LEAVE("wc_BioB64_write", ret);

    return ret;
}

static long wc_BioB64_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{
    WOLFCRYPT_BIO_F_B64_CTX *ctx;
    long ret = 1;
    int i;

    WOLFSSL_ENTER("wc_BioB64_ctrl");

    if (bio == NULL || bio->ptr == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_F_B64_CTX *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            ctx->cont = 1;
            ctx->start = 1;
            ctx->encode = WOLFCRYPT_B64_NONE;
            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_EOF:
            ret = (ctx->cont <= 0 ? 1 :
                   wc_BioCtrl(bio->next_bio, cmd, num, ptr));
            break;

        case BIO_CTRL_WPENDING:
            if (ctx->dataLen < ctx->dataIdx) {
                WOLFSSL_LEAVE("wc_BioB64_write", -1);
                return -1;
            }

            ret = ctx->dataLen - ctx->dataIdx;
            if (!ret && (ctx->encode != WOLFCRYPT_B64_NONE) &&
                (ctx->workLen != 0))
                ret = 1;
            else if (ret <= 0)
                ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_PENDING:
            if (ctx->dataLen < ctx->dataIdx) {
                WOLFSSL_LEAVE("wc_BioB64_write", -1);
                return -1;
            }

            ret = ctx->dataLen - ctx->dataIdx;
            if (ret <= 0)
                ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_FLUSH:
            /* do a final write */
        again:
            while (ctx->dataLen != ctx->dataIdx) {
                i = wc_BioB64_write(bio, NULL, 0);
                if (i < 0)
                    return i;
            }

            if (ctx->workLen != 0) {
                ctx->dataLen = sizeof(ctx->data);

                if (wc_BioGetFlags(bio) & BIO_FLAGS_BASE64_NO_NL)
                    Base64_Encode_NoNl((const byte *)ctx->work, ctx->workLen,
                                       (byte *)ctx->data,
                                       (word32 *)&ctx->dataLen);
                else {
                    Base64_Encode((const byte *)ctx->work, ctx->workLen,
                                  (byte *)ctx->data, (word32 *)&ctx->dataLen);

                    if (ctx->dataLen > (int)sizeof(ctx->data)) {
                        WOLFSSL_LEAVE("wc_BioB64_write", -1);
                        return -1;
                    }
                }

                ctx->dataIdx = 0;
                ctx->workLen = 0;

                goto again;
            }

            /* Finally flush the underlying BIO */
            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_C_DO_STATE_MACHINE:
            wc_BioClearRetryFlags(bio);
            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            wc_BioCopyNextRetry(bio);
            break;

        case BIO_CTRL_DUP:
            break;

        case BIO_CTRL_INFO:
        case BIO_CTRL_GET:
        case BIO_CTRL_SET:
            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;
            
        default:
            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;
    }
    
    WOLFSSL_LEAVE("wc_BioB64_ctrl", (int)ret);
    return ret;
}

static long wc_BioB64_callback_ctrl(WOLFCRYPT_BIO *bio,
                                    int cmd, WOLFCRYPT_BIO_info_cb *fp)
{
    if (bio == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }
    
    WOLFSSL_ENTER("wc_BioB64_callback_ctrl");
    
    return wc_BioCallbackCtrl(bio->next_bio, cmd, fp);
}

static int wc_BioB64_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    WOLFSSL_ENTER("wc_BioB64_puts");
    
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }
    
    return wc_BioB64_write(bio, str, (int)XSTRLEN(str));
}

/* end BIO Filter base64 */

/* start BIO Filter buffer */

typedef struct {
    /*-
     * Buffers are setup like this:
     *
     * <---------------------- size ----------------------->
     * +---------------------------------------------------+
     * | consumed | remaining          | free space        |
     * +---------------------------------------------------+
     * <-- off --><------- len ------->
     */

    /* input buffer */
    char *in;   /* the char array */
    int inSz;   /* how big is the input buffer */
    int inLen;  /* how many bytes are in it */
    int inIdx;  /* write/read offset */

    /* output buffer */
    char *out;  /* the char array */
    int outSz;  /* how big is the output buffer */
    int outLen; /* how many bytes are in it */
    int outIdx; /* write/read offset */

} WOLFCRYPT_BIO_F_BUFFER_CTX;

/* OpenSSL default value */
#define WOLFSSL_F_BUFFER_SIZE_DEFAULT 4096

static int wc_BioBuffer_write(WOLFCRYPT_BIO *bio, const char *buf, int size);
static int wc_BioBuffer_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int wc_BioBuffer_puts(WOLFCRYPT_BIO *bio, const char *str);
static int wc_BioBuffer_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long wc_BioBuffer_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioBuffer_new(WOLFCRYPT_BIO *bio);
static int wc_BioBuffer_free(WOLFCRYPT_BIO *bio);
static long wc_BioBuffer_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                       WOLFCRYPT_BIO_info_cb *fp);

static WOLFCRYPT_BIO_METHOD wc_BioBuffer_method = {
    BIO_TYPE_BUFFER,
    "Buffer",
    wc_BioBuffer_write,
    wc_BioBuffer_read,
    wc_BioBuffer_puts,
    wc_BioBuffer_gets,
    wc_BioBuffer_ctrl,
    wc_BioBuffer_new,
    wc_BioBuffer_free,
    wc_BioBuffer_callback_ctrl,
};


static long wc_BioBuffer_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                       WOLFCRYPT_BIO_info_cb *fp)
{
    if (bio == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    return wc_BioCallbackCtrl(bio->next_bio, cmd, fp);
}

WOLFCRYPT_BIO_METHOD *wc_Bio_f_buffer(void)
{
    return (&wc_BioBuffer_method);
}

static int wc_BioBuffer_new(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio->ptr = (WOLFCRYPT_BIO_F_BUFFER_CTX *)
    XMALLOC(sizeof(WOLFCRYPT_BIO_F_BUFFER_CTX),
            0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    ctx->in = (char *)XMALLOC(WOLFSSL_F_BUFFER_SIZE_DEFAULT, 0,
                              DYNAMIC_TYPE_OPENSSL);
    if (ctx->in == NULL) {
        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
        WOLFSSL_ERROR(MEMORY_E);
        return 0;
    }

    ctx->out = (char *)XMALLOC(WOLFSSL_F_BUFFER_SIZE_DEFAULT, 0,
                               DYNAMIC_TYPE_OPENSSL);
    if (ctx->out == NULL) {
        XFREE(ctx->in, 0, DYNAMIC_TYPE_OPENSSL);
        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
        WOLFSSL_ERROR(MEMORY_E);
        return 0;
    }

    ctx->inSz = WOLFSSL_F_BUFFER_SIZE_DEFAULT;
    ctx->inLen = 0;
    ctx->inIdx = 0;
    ctx->outSz = WOLFSSL_F_BUFFER_SIZE_DEFAULT;
    ctx->outLen = 0;
    ctx->outIdx = 0;

    bio->init = 1;
    bio->flags = 0;
    return 1;
}

static int wc_BioBuffer_free(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;

    WOLFSSL_ENTER("wc_BioBuffer_free");

    if (bio == NULL)
        return 0;

    if (!bio->init || bio->ptr == NULL)
        return 1;

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    if (ctx->in != NULL) {
        XFREE(ctx->in, 0, DYNAMIC_TYPE_OPENSSL);
        ctx->in = NULL;
    }

    if (ctx->out != NULL) {
        XFREE(ctx->out, 0, DYNAMIC_TYPE_OPENSSL);
        ctx->out = NULL;
    }

    XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
    bio->ptr = NULL;

    bio->init = 0;
    bio->flags = 0;
    return 1;
}

static int wc_BioBuffer_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int i, num = 0;
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;

    if (bio == NULL || !bio->init ||
        bio->ptr == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    wc_BioClearRetryFlags(bio);

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    for (;;) {
        i = ctx->inLen;
        if (i != 0) {
            if (i > size)
                i = size;
            XMEMCPY(data, &(ctx->in[ctx->inIdx]), i);
            ctx->inIdx += i;
            ctx->inLen -= i;
            num += i;
            if (size == i)
                return num;
            size -= i;
            data += i;
        }

        /* case of partial read */
        if (size > ctx->inSz) {
            for (;;) {
                i = wc_BioRead(bio->next_bio, data, size);
                if (i <= 0) {
                    wc_BioCopyNextRetry(bio);
                    if (i < 0)
                        return (num > 0 ? num : i);
                    else if (i == 0)
                        return num;
                }
                num += i;

                if (size == i)
                    return num;
                data += i;
                size -= i;
            }
        }

        /* we are going to be doing some buffering */
        i = wc_BioRead(bio->next_bio, ctx->in, ctx->inSz);
        if (i <= 0) {
            wc_BioCopyNextRetry(bio);
            if (i < 0)
                return (num > 0 ? num : i);
            if (i == 0)
                return num;
        }
        ctx->inIdx = 0;
        ctx->inLen = i;
    }

    return 1;
}

static int wc_BioBuffer_write(WOLFCRYPT_BIO *bio,
                              const char *data, int size)
{
    int i, num = 0;
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;

    if (bio == NULL || !bio->init || bio->ptr == NULL ||
        bio->next_bio == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    wc_BioClearRetryFlags(bio);

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    for (;;) {
        i = ctx->outSz - (ctx->outLen + ctx->outIdx);

        /* add to buffer and return */
        if (i >= size) {
            XMEMCPY(&(ctx->out[ctx->outIdx + ctx->outLen]), data, size);
            ctx->outLen += size;
            return (num + size);
        }

        /* stuff already in buffer, so add to it first, then flush */
        if (ctx->outLen != 0) {
            if (i > 0) {
                XMEMCPY(&(ctx->out[ctx->outIdx + ctx->outLen]), data, i);
                data += i;
                size -= i;
                num += i;
                ctx->outLen += i;
            }

            /* we now have a full buffer needing flushing */
            do {
                i = wc_BioWrite(bio->next_bio,
                                &(ctx->out[ctx->outIdx]), ctx->outLen);
                if (i <= 0) {
                    wc_BioCopyNextRetry(bio);

                    if (i < 0)
                        return (num > 0 ? num : i);
                    if (i == 0)
                        return num;
                }

                ctx->outIdx += i;
                ctx->outLen -= i;

            } while (ctx->outLen != 0);
        }

        ctx->outIdx = 0;

        /* we now have size bytes to write */
        while (size >= ctx->outSz) {
            i = wc_BioWrite(bio->next_bio, data, size);
            if (i <= 0) {
                wc_BioCopyNextRetry(bio);
                if (i < 0)
                    return (num > 0 ? num : i);
                if (i == 0)
                    return num;
            }
            num += i;
            data += i;
            size -= i;
            if (size == 0)
                return num;
        }
    }

    return 1;
}

static long wc_BioBuffer_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{

    int i, *ip, ibs, obs;
    long ret = 1;
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;

    if (bio == NULL || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            ctx->inLen = 0;
            ctx->inIdx = 0;
            ctx->outLen = 0;
            ctx->outIdx = 0;

            if (bio->next_bio == NULL)
                return 0;

            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_INFO:
            ret = (long)ctx->outLen;
            break;

        case BIO_C_GET_BUFF_NUM_LINES:
            ret = 0;
            for (i = 0; i < ctx->inLen; i++) {
                if (ctx->in[ctx->inIdx + i] == '\n')
                    ret++;
            }
            break;

        case BIO_CTRL_WPENDING:
            ret = (long)ctx->outLen;
            if (ret == 0) {
                if (bio->next_bio == NULL)
                    return 0;
                ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            }
            break;

        case BIO_CTRL_PENDING:
            ret = (long)ctx->inLen;
            if (ret == 0) {
                if (bio->next_bio == NULL)
                    return 0;
                ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            }
            break;

        case BIO_C_SET_BUFF_READ_DATA:
            if (num > ctx->inSz) {
                ctx->in = XREALLOC(ctx->in, num, 0, DYNAMIC_TYPE_OPENSSL);
                if (ctx->in == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    return 0;
                }
            }

            ctx->inIdx = 0;
            ctx->inLen = (int)num;
            XMEMCPY(ctx->in, ptr, num);
            ret = 1;
            break;

        case BIO_C_SET_BUFF_SIZE:
            if (ptr != NULL) {
                ip = (int *)ptr;
                if (*ip == 0) {
                    ibs = (int)num;
                    obs = ctx->outSz;
                } else {
                    ibs = ctx->inSz;
                    obs = (int)num;
                }
            } else {
                ibs = (int)num;
                obs = (int)num;
            }

            if ((ibs > WOLFSSL_F_BUFFER_SIZE_DEFAULT) && (ibs != ctx->inSz)) {
                ctx->in = XREALLOC(ctx->in, num, 0, DYNAMIC_TYPE_OPENSSL);
                if (ctx->in == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    return 0;
                }

                ctx->inIdx = 0;
                ctx->inLen = 0;
                ctx->inSz = ibs;
            }

            if ((obs > WOLFSSL_F_BUFFER_SIZE_DEFAULT) && (obs != ctx->outSz)) {
                ctx->out = XREALLOC(ctx->out, num, 0, DYNAMIC_TYPE_OPENSSL);
                if (ctx->out == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    return 0;
                }

                ctx->outIdx = 0;
                ctx->outLen = 0;
                ctx->outSz = obs;
            }
            break;

        case BIO_C_DO_STATE_MACHINE:
            if (bio->next_bio == NULL) {
                WOLFSSL_ERROR(BAD_FUNC_ARG);
                return 0;
            }

            wc_BioClearRetryFlags(bio);
            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            wc_BioCopyNextRetry(bio);
            break;

        case BIO_CTRL_FLUSH:
            if (bio->next_bio == NULL) {
                WOLFSSL_ERROR(BAD_FUNC_ARG);
                return 0;
            }

            if (ctx->outLen <= 0) {
                ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
                break;
            }

            for (;;) {
                wc_BioClearRetryFlags(bio);
                if (ctx->outLen > 0) {
                    ret = wc_BioWrite(bio->next_bio,
                                      &(ctx->out[ctx->outIdx]), ctx->outLen);
                    wc_BioCopyNextRetry(bio);
                    if (ret <= 0)
                        return ret;
                    ctx->outIdx += ret;
                    ctx->outLen -= ret;
                } else {
                    ctx->outLen = 0;
                    ctx->outIdx = 0;
                    ret = 1;
                    break;
                }
            }

            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_DUP:
            ret = wc_BioSetReadBufferSize((WOLFCRYPT_BIO *)ptr, ctx->inSz);
            if (!ret)
                break;

            ret = wc_BioSetWriteBufferSize((WOLFCRYPT_BIO *)ptr, ctx->outSz);
            if (!ret)
                break;

            ret = 1;
            break;

        default:
            if (bio->next_bio == NULL)
                return 0;

            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;
    }

    return ret;
}

static int wc_BioBuffer_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    WOLFCRYPT_BIO_F_BUFFER_CTX *ctx;
    int num = 0, i, flag;

    if (bio == NULL || bio->ptr == NULL || buf == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    wc_BioClearRetryFlags(bio);

    ctx = (WOLFCRYPT_BIO_F_BUFFER_CTX *)bio->ptr;

    /* to put end of string */
    size--;

    for (;;) {
        if (ctx->inLen > 0) {
            flag = 0;

            for (i = 0; (i < ctx->inLen) && (i < size); i++) {
                *(buf++) = ctx->in[ctx->inIdx+i];
                if (ctx->in[ctx->inIdx+i] == '\n') {
                    flag = 1;
                    i++;
                    break;
                }
            }
            num += i;
            size -= i;
            ctx->inLen -= i;
            ctx->inIdx += i;
            if (flag || !size) {
                *buf = '\0';
                return num;
            }
        } else {
            i = wc_BioRead(bio->next_bio, ctx->in, ctx->inSz);
            if (i <= 0) {
                wc_BioCopyNextRetry(bio);
                *buf = '\0';
                if (i < 0)
                    return (num > 0 ? num : i);
                if (i == 0)
                    return num;
            }
            ctx->inLen = i;
            ctx->inIdx = 0;
        }
    }
    
    return i;
}

static int wc_BioBuffer_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }
    
    return wc_BioBuffer_write(bio, str, (int)XSTRLEN(str));
}

/* end BIO Filter buffer */

/* start BIO Filter cipher */

typedef struct {
    int dataLen;
    int dataIdx;
    int cont;
    int finished;
    int ok; /* bad decrypt */

    WOLFCRYPT_EVP_CIPHER_CTX cipher;
    /*
     * buf is larger than ENC_BLOCK_SIZE because EVP_DecryptUpdate can return
     * up to a block more data than is presented to it
     */

#define WOLFCRYPT_ENC_BLOCK_SIZE  128
#define WOLFCRYPT_BUF_OFFSET      64

    byte data[WOLFCRYPT_ENC_BLOCK_SIZE + WOLFCRYPT_BUF_OFFSET + 2];
} WOLFCRYPT_BIO_ENC_CTX;


static int wc_BioCipher_write(WOLFCRYPT_BIO *bio, const char *buf, int size);
static int wc_BioCipher_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static long wc_BioCipher_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioCipher_new(WOLFCRYPT_BIO *bio);
static int wc_BioCipher_free(WOLFCRYPT_BIO *bio);
static long wc_BioCipher_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                       WOLFCRYPT_BIO_info_cb *fp);

static WOLFCRYPT_BIO_METHOD wc_BioCipher_method = {
    BIO_TYPE_CIPHER,
    "Cipher",
    wc_BioCipher_write,
    wc_BioCipher_read,
    NULL, /* puts */
    NULL, /* gets */
    wc_BioCipher_ctrl,
    wc_BioCipher_new,
    wc_BioCipher_free,
    wc_BioCipher_callback_ctrl,
};

static long wc_BioCipher_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                       WOLFCRYPT_BIO_info_cb *fp)
{
    WOLFSSL_ENTER("wc_BioCipher_callback_ctrl");
    if (bio == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    return  wc_BioCallbackCtrl(bio->next_bio, cmd, fp);
}

WOLFCRYPT_BIO_METHOD *wc_Bio_f_cipher(void)
{
    WOLFSSL_ENTER("WOLFCRYPT_BIO_f_cipher");
    return (&wc_BioCipher_method);
}

void wc_BioSetCipher(WOLFCRYPT_BIO *bio, const WOLFCRYPT_EVP_CIPHER *cipher,
                     const unsigned char *key, const unsigned char *iv, int enc)
{
    WOLFCRYPT_BIO_ENC_CTX *ctx;

    WOLFSSL_ENTER("wc_BioSetCipher");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return;
    }


    if ((bio->callback != NULL) &&
        bio->callback(bio, BIO_CB_CTRL, (const char *)cipher,
                      BIO_CTRL_SET, enc, 0) <= 0) {
            WOLFSSL_ERROR(BIO_CALLBACK_E);
            return;
        }

    bio->init = 1;

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    wc_EVP_CipherInit(&(ctx->cipher), cipher, (unsigned char *)key,
                      (unsigned char *)iv, enc);

    if ((bio->callback != NULL) &&
        bio->callback(bio, BIO_CB_CTRL, (const char *)cipher,
                      BIO_CTRL_SET, enc, 1) <= 0) {
        WOLFSSL_ERROR(BIO_CALLBACK_E);
        }
}

static int wc_BioCipher_new(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_ENC_CTX *ctx;

    WOLFSSL_ENTER("wc_BioCipher_new");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->ptr = (WOLFCRYPT_BIO_ENC_CTX *)XMALLOC(sizeof(WOLFCRYPT_BIO_ENC_CTX),
                                                0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return -1;
    }

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    wc_EVP_CIPHER_CTX_init(&ctx->cipher);

    ctx->dataLen = 0;
    ctx->dataIdx = 0;
    ctx->cont = 1;
    ctx->finished = 0;
    ctx->ok = 1;

    bio->init = 0;
    bio->flags = 0;

    WOLFSSL_LEAVE("wc_BioCipher_new", 1);
    return 1;
}

static int wc_BioCipher_free(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_ENC_CTX *ctx;

    WOLFSSL_ENTER("wc_BioCipher_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    wc_EVP_CIPHER_CTX_cleanup(&(ctx->cipher));

    XMEMSET(bio->ptr, 0, sizeof(WOLFCRYPT_BIO_ENC_CTX));
    XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
    bio->ptr = NULL;

    bio->init = 0;
    bio->flags = 0;

    WOLFSSL_LEAVE("wc_BioCipher_free", 1);
    return 1;
}

static int wc_BioCipher_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 0, i;
    WOLFCRYPT_BIO_ENC_CTX *ctx;

    WOLFSSL_ENTER("wc_BioCipher_read");

    if (bio == NULL || data == NULL ||
        bio->ptr == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    /* First check if there are bytes decoded/encoded */
    if (ctx->dataLen > 0) {
        i = ctx->dataLen - ctx->dataIdx;
        if (i > size)
            i = size;

        XMEMCPY(data, &ctx->data[ctx->dataIdx], i);
        ret = i;
        data += i;
        size -= i;
        ctx->dataIdx += i;

        /* all read */
        if (ctx->dataLen == ctx->dataIdx)
            ctx->dataLen = ctx->dataIdx = 0;
    }

    /*
     * At this point, we have room of size bytes and an empty buffer, so we
     * should read in some more.
     */
    while (size > 0) {
        if (ctx->cont <= 0)
            break;

        /* read in at IV offset, read the EVP_Cipher documentation about why
         */
        i = wc_BioRead(bio->next_bio, &ctx->data[WOLFCRYPT_BUF_OFFSET],
                       WOLFCRYPT_ENC_BLOCK_SIZE);
        if (i <= 0) {
            /* Should be continue next time we are called ? */
            if (!wc_BioShouldRetry(bio->next_bio)) {
                ctx->cont = i;

                i = wc_EVP_CipherFinal(&ctx->cipher, ctx->data,
                                       &ctx->dataLen);

                ctx->ok = i;
                ctx->dataIdx = 0;
            } else {
                if (!ret)
                    ret = i;
                break;
            }
        } else {
            wc_EVP_CipherUpdate(&ctx->cipher,
                                ctx->data, &ctx->dataLen,
                                &ctx->data[WOLFCRYPT_BUF_OFFSET], i);
            ctx->cont = 1;

            if (!ctx->dataLen)
                continue;
        }

        i = (ctx->dataLen <= size ? ctx->dataLen : size);
        if (i <= 0)
            break;

        XMEMCPY(data, ctx->data, i);

        ret += i;
        ctx->dataIdx = i;
        size -= i;
        data += i;
    }

    wc_BioClearRetryFlags(bio);
    wc_BioCopyNextRetry(bio);

    return (!ret ? ctx->cont : ret);
}

static int wc_BioCipher_write(WOLFCRYPT_BIO *bio,
                              const char *data, int size)
{
    int ret, n, i;
    WOLFCRYPT_BIO_ENC_CTX *ctx;

    WOLFSSL_ENTER("wc_BioCipher_write");

    if (bio == NULL || bio->ptr == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    ret = size;

    wc_BioClearRetryFlags(bio);

    n = ctx->dataLen - ctx->dataIdx;
    while (n > 0) {
        i = wc_BioWrite(bio->next_bio, &ctx->data[ctx->dataIdx], n);
        if (i <= 0) {
            wc_BioCopyNextRetry(bio);
            return i;
        }
        ctx->dataIdx += i;
        n -= i;
    }

    /* at this point all pending data has been written
     * return if we haven't new data to write */
    if (data == NULL || size <= 0)
        return 0;

    while (size > 0) {
        n = (size > WOLFCRYPT_ENC_BLOCK_SIZE ? WOLFCRYPT_ENC_BLOCK_SIZE : size);
        wc_EVP_CipherUpdate(&ctx->cipher, ctx->data, &ctx->dataLen,
                            (byte *)data, n);

        size -= n;
        data += n;

        ctx->dataIdx = 0;
        n = ctx->dataLen;
        while (n > 0) {
            i = wc_BioWrite(bio->next_bio, &ctx->data[ctx->dataIdx], n);
            if (i <= 0) {
                wc_BioCopyNextRetry(bio);
                return (ret == size ? i : ret - size);
            }
            n -= i;
            ctx->dataIdx += i;
        }
        ctx->dataLen = 0;
        ctx->dataIdx = 0;
    }

    wc_BioCopyNextRetry(bio);
    return ret;
}

static long wc_BioCipher_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                              long num, void *ptr)
{
    WOLFCRYPT_BIO_ENC_CTX *ctx;
    long ret = 1;
    int i;

    WOLFSSL_ENTER("wc_BioCipher_ctrl");

    if (bio == NULL || bio->ptr == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    ctx = (WOLFCRYPT_BIO_ENC_CTX *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            ctx->ok = 1;
            ctx->finished = 0;
            wc_EVP_CipherInit(&ctx->cipher, NULL, NULL, NULL,
                              ctx->cipher.enc);
            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_EOF:         /* More to read */
            if (ctx->cont <= 0)
                ret = 1;
            else
                ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_WPENDING:
        case BIO_CTRL_PENDING:
            ret = ctx->dataLen - ctx->dataIdx;
            if (ret <= 0)
                ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_CTRL_FLUSH:
        loop:
            while (ctx->dataLen != ctx->dataIdx) {
                i = wc_BioCipher_write(bio, NULL, 0);
                if (i < 0)
                    return i;
            }

            if (!ctx->finished) {
                ctx->finished = 1;
                ctx->dataIdx = 0;

                ret = wc_EVP_CipherFinal(&ctx->cipher, ctx->data,
                                         &ctx->dataLen);
                ctx->ok = (int)ret;
                if (ret <= 0)
                    break;

                goto loop;
            }

            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_C_GET_CIPHER_STATUS:
            ret = (long)ctx->ok;
            break;

        case BIO_C_DO_STATE_MACHINE:
            wc_BioClearRetryFlags(bio);
            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            wc_BioCopyNextRetry(bio);
            break;

        case BIO_C_GET_CIPHER_CTX:
        {
            WOLFCRYPT_EVP_CIPHER_CTX **c_ctx;
            c_ctx = (WOLFCRYPT_EVP_CIPHER_CTX **)ptr;
            *c_ctx = &ctx->cipher;
            bio->init = 1;
        }
            break;

        case BIO_CTRL_DUP:
        {
            WOLFCRYPT_BIO *dbio;
            WOLFCRYPT_BIO_ENC_CTX *dctx;

            dbio = (WOLFCRYPT_BIO *)ptr;
            dctx = (WOLFCRYPT_BIO_ENC_CTX *)dbio->ptr;

            wc_EVP_CIPHER_CTX_init(&dctx->cipher);
            ret = wc_EVP_CIPHER_CTX_copy(&dctx->cipher, &ctx->cipher);
            if (ret)
                dbio->init = 1;
        }
            break;
            
        default:
            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;
    }
    
    WOLFSSL_LEAVE("wc_BioCipher_ctrl", (int)ret);
    return ret;
}

/* end BIO Filter cipher */

/* start BIO Filter digest */

static int wc_BioDigest_write(WOLFCRYPT_BIO *bio, const char *buf, int size);
static int wc_BioDigest_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int wc_BioDigest_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long wc_BioDigest_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioDigest_new(WOLFCRYPT_BIO *bio);
static int wc_BioDigest_free(WOLFCRYPT_BIO *bio);
static long wc_BioDigest_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                       WOLFCRYPT_BIO_info_cb *fp);

static WOLFCRYPT_BIO_METHOD wc_BioDigest_method = {
    BIO_TYPE_MD,
    "Message digest",
    wc_BioDigest_write,
    wc_BioDigest_read,
    NULL, /* puts */
    wc_BioDigest_gets,
    wc_BioDigest_ctrl,
    wc_BioDigest_new,
    wc_BioDigest_free,
    wc_BioDigest_callback_ctrl,
};

static long wc_BioDigest_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                       WOLFCRYPT_BIO_info_cb *fp)
{
    WOLFSSL_ENTER("wc_BioDigest_callback_ctrl");
    if (bio == NULL || bio->next_bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    return  wc_BioCallbackCtrl(bio->next_bio, cmd, fp);
}

WOLFCRYPT_BIO_METHOD *wc_Bio_f_md(void)
{
    return (&wc_BioDigest_method);
}

static int wc_BioDigest_new(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioDigest_new");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->ptr = (WOLFCRYPT_EVP_MD_CTX *)XMALLOC(sizeof(WOLFCRYPT_EVP_MD_CTX),
                                               0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return -1;
    }

    wc_EVP_MD_CTX_init((WOLFCRYPT_EVP_MD_CTX *)bio->ptr);

    bio->init = 0;
    bio->flags = 0;

    WOLFSSL_LEAVE("wc_BioDigest_new", 1);
    return 1;
}

static int wc_BioDigest_free(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioDigest_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    wc_EVP_MD_CTX_cleanup((WOLFCRYPT_EVP_MD_CTX *)bio->ptr);

    XMEMSET(bio->ptr, 0, sizeof(WOLFCRYPT_EVP_MD_CTX));
    XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
    bio->ptr = NULL;

    bio->init = 0;
    bio->flags = 0;

    WOLFSSL_LEAVE("wc_BioDigest_free", 1);
    return 1;
}

static int wc_BioDigest_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    WOLFCRYPT_EVP_MD_CTX *ctx;
    int ret = 0;

    WOLFSSL_ENTER("wc_BioDigest_read");

    if (bio == NULL || bio->ptr == NULL || bio->next_bio == NULL ||
        data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_EVP_MD_CTX *)bio->ptr;

    ret = wc_BioRead(bio->next_bio, data, size);
    if (bio->init && ret > 0) {
        if (wc_EVP_DigestUpdate(ctx, data, (word32)ret) != 1) {
            WOLFSSL_ERROR(BIO_DGST_UPDATE_E);
            return -1;
        }
    }

    wc_BioClearRetryFlags(bio);
    wc_BioCopyNextRetry(bio);

    WOLFSSL_LEAVE("wc_BioDigest_read", ret);
    return ret;
}

static int wc_BioDigest_write(WOLFCRYPT_BIO *bio,
                              const char *data, int size)
{
    WOLFCRYPT_EVP_MD_CTX *ctx;
    int ret = 0;

    WOLFSSL_ENTER("wc_BioDigest_write");

    if (bio == NULL || bio->ptr == NULL || data == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_EVP_MD_CTX *)bio->ptr;

    ret = wc_BioWrite(bio->next_bio, data, size);

    if (bio->init && ret > 0) {
        if (wc_EVP_DigestUpdate(ctx, data, (word32)ret) != 1) {
            WOLFSSL_ERROR(BIO_DGST_UPDATE_E);
            wc_BioClearRetryFlags(bio);
            return -1;
        }
    }

    if (bio->next_bio != NULL) {
        wc_BioClearRetryFlags(bio);
        wc_BioCopyNextRetry(bio);
    }

    WOLFSSL_LEAVE("wc_BioDigest_write", ret);

    return ret;
}

static long wc_BioDigest_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{
    WOLFCRYPT_EVP_MD_CTX *ctx;
    long ret = 1;

    WOLFSSL_ENTER("wc_BioDigest_ctrl");

    if (bio == NULL || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    ctx = (WOLFCRYPT_EVP_MD_CTX *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            if (bio->init)
                ret = wc_EVP_DigestInit(ctx, ctx->digest);
            else
                ret = 0;

            if (ret > 0)
                ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;

        case BIO_C_GET_MD:
            if (bio->init) {
                const WOLFCRYPT_EVP_MD **pmd;
                pmd = (const WOLFCRYPT_EVP_MD **)ptr;
                *pmd = ctx->digest;
            } else
                ret = 0;
            break;

        case BIO_C_GET_MD_CTX:
        {
            WOLFCRYPT_EVP_MD_CTX **pctx;
            pctx = (WOLFCRYPT_EVP_MD_CTX **)ptr;
            *pctx = ctx;
        }
            bio->init = 1;
            break;

        case BIO_C_SET_MD_CTX:
            if (bio->init)
                bio->ptr = ptr;
            else
                ret = 0;
            break;

        case BIO_C_DO_STATE_MACHINE:
            wc_BioClearRetryFlags(bio);
            ret =  wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            wc_BioCopyNextRetry(bio);
            break;

        case BIO_C_SET_MD:
            ret = wc_EVP_DigestInit(ctx, (WOLFCRYPT_EVP_MD *)ptr);
            if (ret > 0)
                bio->init = 1;
            else {
                WOLFSSL_ERROR(BIO_DGST_INIT_E);
            }
            break;

        case BIO_CTRL_DUP:
        {
            WOLFCRYPT_BIO   *dbio;
            WOLFCRYPT_EVP_MD_CTX  *dctx;

            dbio = (WOLFCRYPT_BIO *)ptr;
            dctx = (WOLFCRYPT_EVP_MD_CTX *)dbio->ptr;

            ret = wc_EVP_MD_CTX_copy(dctx, ctx);
            if (ret)
                bio->init = 1;
        }
            break;

        default:
            ret = wc_BioCtrl(bio->next_bio, cmd, num, ptr);
            break;
    }

    WOLFSSL_LEAVE("wc_BioDigest_ctrl", (int)ret);
    return ret;
}

static int wc_BioDigest_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    WOLFCRYPT_EVP_MD_CTX *ctx;
    unsigned int dgstLen = 0;

    WOLFSSL_ENTER("wc_BioDigest_gets");

    if (bio == NULL || bio->ptr == NULL || buf == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    ctx = (WOLFCRYPT_EVP_MD_CTX *)bio->ptr;

    if (size < ctx->macSize) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }
    
    if (wc_EVP_DigestFinal(ctx, (byte *)buf, &dgstLen) != 1) {
        WOLFSSL_ERROR(BIO_DGST_FINAL_E);
        return -1;
    }
    
    return dgstLen;
}

/* end BIO Filter digest */

/* start BIO Filter socket */

/* Socket Handling */
#ifndef WOLFSSL_SOCKET_INVALID
#ifdef USE_WINDOWS_API
#define WOLFSSL_SOCKET_INVALID  ((SOCKET)INVALID_SOCKET)
#else
#define WOLFSSL_SOCKET_INVALID  (0)
#endif
#endif /* WOLFSSL_SOCKET_INVALID */

#define MAX_LISTEN  32

#ifdef USE_WINDOWS_API
static int wsa_init_done = 0;
#endif

int wc_BioGetHostIp(const char *str, unsigned char *ip)
{
    struct hostent *he;
    unsigned int iip[4];

    if (wc_BioSockInit() != 1)
        return 0;

    /* IP found */
    if (sscanf(str, "%d.%d.%d.%d", &iip[0], &iip[1], &iip[2], &iip[3]) == 4)
    {
        ip[0] = (iip[0] & 0xff);
        ip[1] = (iip[1] & 0xff);
        ip[2] = (iip[2] & 0xff);
        ip[3] = (iip[3] & 0xff);
        return 1;
    }

    /* IP not found, check with a gethostbyname */
    he = gethostbyname(str);
    if (he == NULL) {
        WOLFSSL_ERROR(BIO_NO_HOSTNAME_E);
        return 0;
    }

    if (he->h_addrtype != AF_INET) {
        WOLFSSL_ERROR(BIO_ADDR_AF_INET_E);
        return 0;
    }

    XMEMCPY(ip, he->h_addr_list[0], 4);

    return 1;
}

int wc_BioGetPort(const char *str, unsigned short *port_ptr)
{
    int i;
    struct servent *s = NULL;

    if (str == NULL) {
        WOLFSSL_ERROR(BIO_NO_PORT_E);
        return 0;
    }

    i = atoi(str);
    if (i != 0) {
        *port_ptr = (unsigned short)i;
        return 1;
    }

    s = getservbyname(str, "tcp");
    if (s != NULL) {
        *port_ptr = ntohs((unsigned short)s->s_port);
        return 1;
    }

    if (strcmp(str, "http") == 0)
        *port_ptr = 80;
    else if (strcmp(str, "telnet") == 0)
        *port_ptr = 23;
    else if (strcmp(str, "socks") == 0)
        *port_ptr = 1080;
    else if (strcmp(str, "https") == 0)
        *port_ptr = 443;
    else if (strcmp(str, "ssl") == 0)
        *port_ptr = 443;
    else if (strcmp(str, "ftp") == 0)
        *port_ptr = 21;
    else if (strcmp(str, "gopher") == 0)
        *port_ptr = 70;
    else {
        WOLFSSL_ERROR(BIO_SRV_PROTO_E);
        return 0;
    }

    return 1;
}

int wc_BioSockError(int sock)
{
    int j = 0, i;
    union {
        size_t s;
        int i;
    } size;

    /* heuristic way to adapt for platforms that expect 64-bit optlen */
    size.s = 0, size.i = sizeof(j);
    /*
     * Note: under Windows the third parameter is of type (char *) whereas
     * under other systems it is (void *) if you don't have a cast it will
     * choke the compiler: if you do have a cast then you can either go for
     * (char *) or (void *).
     */
    i = getsockopt(sock, SOL_SOCKET, SO_ERROR, (void *)&j, (void *)&size);
    if (i < 0)
        return 1;

    return j;
}

int wc_BioSockInit(void)
{
# ifdef USE_WINDOWS_API
    static struct WSAData wsa_state;

    if (!wsa_init_done) {
        int err;

        wsa_init_done = 1;
        XMEMSET(&wsa_state, 0, sizeof(wsa_state));
        /*
         * Not making wsa_state available to the rest of the code is formally
         * wrong. But the structures we use are [beleived to be] invariable
         * among Winsock DLLs, while API availability is [expected to be]
         * probed at run-time with DSO_global_lookup.
         */
        if (WSAStartup(0x0202, &wsa_state) != 0) {
            err = WSAGetLastError();
            WOLFSSL_ERROR(BIO_WSASTARTUP_E);
            return -1;
        }
    }
# endif /* USE_WINDOWS_API */

    return 1;
}

void wc_BioSockCleanup(void)
{
#ifdef USE_WINDOWS_API
    if (wsa_init_done) {
        wsa_init_done = 0;
        WSACleanup();
    }
#endif
}

int wc_BioGetAcceptSocket(char *host, int bind_mode)
{
    int ret = 0;
    union {
        struct sockaddr sa;
        struct sockaddr_in sa_in;
        struct sockaddr_in6 sa_in6;
    } server, client;
    int s = WOLFSSL_SOCKET_INVALID, cs, addrlen;
    unsigned char ip[4];
    unsigned short port;
    char *str = NULL;
    char *h, *p, *e;
    unsigned long l;
    int err_num;

    if (wc_BioSockInit() != 1)
        return WOLFSSL_SOCKET_INVALID;

    str = strdup(host);
    if (str == NULL)
        return WOLFSSL_SOCKET_INVALID;

    h = p = NULL;
    h = str;
    for (e = str; *e; e++) {
        if (*e == ':') {
            p = e;
        } else if (*e == '/') {
            *e = '\0';
            break;
        }
    }
    if (p)
        *p++ = '\0';            /* points at last ':', '::port' is special
                                 * [see below] */
    else
        p = h, h = NULL;

    if (!wc_BioGetPort(p, &port))
        goto err;

    XMEMSET((char *)&server, 0, sizeof(server));
    server.sa_in.sin_family = AF_INET;
    server.sa_in.sin_port = htons(port);
    addrlen = sizeof(server.sa_in);

    if (h == NULL || strcmp(h, "*") == 0)
        server.sa_in.sin_addr.s_addr = INADDR_ANY;
    else {
        if (!wc_BioGetHostIp(h, &(ip[0])))
            goto err;
        l = (unsigned long)
        ((unsigned long)ip[0] << 24L) |
        ((unsigned long)ip[1] << 16L) |
        ((unsigned long)ip[2] << 8L)  |
        ((unsigned long)ip[3]);
        server.sa_in.sin_addr.s_addr = htonl(l);
    }

again:
    s = socket(server.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == WOLFSSL_SOCKET_INVALID) {
        WOLFSSL_ERROR(BIO_CREATE_SOCKET_E);
        goto err;
    }

#ifdef SO_REUSEADDR
    if (bind_mode == BIO_BIND_REUSEADDR) {
        int i = 1;

        ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&i, sizeof(i));
        bind_mode = BIO_BIND_NORMAL;
    }
#endif /* SO_REUSEADDR */
    if (bind(s, &server.sa, addrlen) == -1) {
#ifdef SO_REUSEADDR
#ifdef USE_WINDOWS_API
        err_num = WSAGetLastError();
        if ((bind_mode == BIO_BIND_REUSEADDR_IF_UNUSED) &&
            (err_num == WSAEADDRINUSE))
#else
            err_num = errno;
        if ((bind_mode == BIO_BIND_REUSEADDR_IF_UNUSED) &&
            (err_num == EADDRINUSE))
#endif /* USE_WINDOWS_API */
        {
            client = server;
            if (h == NULL || !strcmp(h, "*")) {
                if (client.sa.sa_family == AF_INET6) {
                    XMEMSET(&client.sa_in6.sin6_addr, 0,
                            sizeof(client.sa_in6.sin6_addr));
                    client.sa_in6.sin6_addr.s6_addr[15] = 1;
                }
                else if (client.sa.sa_family == AF_INET)
                    client.sa_in.sin_addr.s_addr = htonl(0x7F000001);
                else
                    goto err;
            }

            cs = socket(client.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
            if (cs != WOLFSSL_SOCKET_INVALID) {
                int ii;
                ii = connect(cs, &client.sa, addrlen);
#ifdef USE_WINDOWS_API
                closesocket(cs);
#else
                close(cs);
#endif
                if (ii == WOLFSSL_SOCKET_INVALID) {
                    bind_mode = BIO_BIND_REUSEADDR;
#ifdef USE_WINDOWS_API
                    closesocket(s);
#else
                    close(s);
#endif
                    goto again;
                }
            }
        }
#endif /* SO_REUSEADDR */

        WOLFSSL_ERROR(BIO_BIND_SOCKET_E);
        goto err;
    }

    if (listen(s, MAX_LISTEN) == -1) {
        WOLFSSL_ERROR(BIO_LISTEN_SOCKET_E);
        goto err;
    }

    ret = 1;

err:

    if (str != NULL)
        free(str);

    if (!ret && (s != WOLFSSL_SOCKET_INVALID)) {
#ifdef USE_WINDOWS_API
        closesocket(s);
#else
        close(s);
#endif
        s = WOLFSSL_SOCKET_INVALID;
    }

    return s;
}

int wc_BioAccept(int sock, char **addr)
{
    int dsock = WOLFSSL_SOCKET_INVALID, idx, ret;
    unsigned long l;

    struct {
        union {
            size_t s;
            int i;
        } len;
        union {
            struct sockaddr sa;
            struct sockaddr_in sa_in;
            struct sockaddr_in sa_in6;
        } from;
    } sa;

    sa.len.s = 0;
    sa.len.i = sizeof(sa.from);
    XMEMSET(&sa.from, 0, sizeof(sa.from));

    dsock = accept(sock, &sa.from.sa, (void *)&sa.len);
    if (sizeof(sa.len.i) != sizeof(sa.len.s) && !sa.len.i) {
        if (sa.len.s > sizeof(sa.from)) {
            WOLFSSL_ERROR(MEMORY_E);
            dsock = WOLFSSL_SOCKET_INVALID;
            goto end;
        }

        sa.len.i = (int)sa.len.s;
    }

    if (dsock == WOLFSSL_SOCKET_INVALID) {
        if (wc_BioSockShouldRetry(dsock))
            return -2;
        WOLFSSL_ERROR(BIO_ACCEPT_E);
        goto end;
    }

    if (addr == NULL || sa.from.sa.sa_family != AF_INET)
        goto end;

    if (*addr == NULL) {
        *addr = XMALLOC(24, 0, DYNAMIC_TYPE_OPENSSL);
        if (*addr == NULL) {
            WOLFSSL_ERROR(MEMORY_E);
            goto end;
        }
    }

    l = ntohl(sa.from.sa_in.sin_addr.s_addr);

    ret = wc_BioIntToStr((unsigned char)(l >> 24L) & 0xff, *addr, 24);
    if (ret <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        dsock = WOLFSSL_SOCKET_INVALID;
        goto end;
    }
    idx = ret;
    *(*addr+(idx++)) = '.';
    ret = wc_BioIntToStr((unsigned char)(l >> 16L) & 0xff, *addr+idx, 24-idx);
    if (ret <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        dsock = WOLFSSL_SOCKET_INVALID;
        goto end;
    }
    idx += ret;
    *(*addr+(idx++)) = '.';
    ret = wc_BioIntToStr((unsigned char)(l >> 8L) & 0xff, *addr+idx, 24-idx);
    if (ret <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        dsock = WOLFSSL_SOCKET_INVALID;
        goto end;
    }
    idx += ret;
    *(*addr+(idx++)) = '.';
    ret = wc_BioIntToStr((unsigned char)(l) & 0xff, *addr+idx, 24-idx);
    if (ret <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        dsock = WOLFSSL_SOCKET_INVALID;
        goto end;
    }
    idx += ret;
    *(*addr+(idx++)) = ':';
    ret = wc_BioIntToStr(ntohs(sa.from.sa_in.sin_port), *addr+idx, 24-idx);
    if (ret <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        dsock = WOLFSSL_SOCKET_INVALID;
        goto end;
    }

end:
    return dsock;
}

int wc_BioSetTcpNsigpipe(int s, int on)
{
    int ret = 0;

#ifndef USE_WINDOWS_API
#ifdef SO_NOSIGPIPE
    ret = setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#else  /* no S_NOSIGPIPE */
    (void) s;
    (void) on;

    signal(SIGPIPE, SIG_IGN);
#endif /* S_NOSIGPIPE */
#else /* USE_WINDOWS_API */
    (void) s;
    (void) on;
#endif /* USE_WINDOWS_API */

    return (ret == 0);
}

int wc_BioSetTcpNdelay(int s, int on)
{
    int ret = 0;
#if defined(TCP_NODELAY)
#ifdef SOL_TCP
    int opt = SOL_TCP;
#else
    int opt = IPPROTO_TCP;
#endif

    ret = setsockopt(s, opt, TCP_NODELAY, (char *)&on, sizeof(on));
#else
    (void) s;
    (void) on;
#endif /* TCP_NODELAY */

    return (ret == 0);
}

int wc_BioSocketNbio(int s, int mode)
{
#ifdef USE_WINDOWS_API
    unsigned long blocking = mode;
    int ret = ioctlsocket(s, FIONBIO, &blocking);
    return (ret == 0);
#elif defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET) \
|| defined (WOLFSSL_TIRTOS)|| defined(WOLFSSL_VXWORKS)
    /* non blocking not supported, for now */
    return -1;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags)
        flags = fcntl(s, F_SETFL, flags | mode);
    return (flags == 0);
#endif
}

/* end BIO Filter socket */

/* start BIO Method accept */

typedef struct {
    int state;
    int nbio;

    char *param_addr;
    char *ip_port;
    int accept_sock;
    int accept_nbio;

    /*
     * If 0, it means normal, if 1, do a connect on bind failure, and if
     * there is no-one listening, bind with SO_REUSEADDR. If 2, always use
     * SO_REUSEADDR.
     */
    int bind_mode;

    /* used to force some socket options like NO_SIGPIPE, TCP_NODELAY */
    int options;

    WOLFCRYPT_BIO *bio_chain;
} WOLFCRYPT_BIO_ACCEPT;

static int wc_BioAccept_write(WOLFCRYPT_BIO *bio, const char *data, int size);
static int wc_BioAccept_read(WOLFCRYPT_BIO *bio, char *data, int size);
static int wc_BioAccept_puts(WOLFCRYPT_BIO *bio, const char *str);
static long wc_BioAccept_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioAccept_new(WOLFCRYPT_BIO *bio);
static int wc_BioAccept_free(WOLFCRYPT_BIO *bio);
static void wc_BioAccept_close_socket(WOLFCRYPT_BIO *bio);

static int wc_BioAccept_state(WOLFCRYPT_BIO *bio, WOLFCRYPT_BIO_ACCEPT *c);

# define ACPT_S_BEFORE                   1
# define ACPT_S_GET_ACCEPT_SOCKET        2
# define ACPT_S_OK                       3

static WOLFCRYPT_BIO_METHOD wc_BioAccept_method = {
    BIO_TYPE_ACCEPT,
    "Socket accept",
    wc_BioAccept_write,
    wc_BioAccept_read,
    wc_BioAccept_puts,
    NULL, /* gets */
    wc_BioAccept_ctrl,
    wc_BioAccept_new,
    wc_BioAccept_free,
    NULL,
};

WOLFCRYPT_BIO_METHOD *wc_Bio_s_accept(void)
{
    return (&wc_BioAccept_method);
}

static int wc_BioAccept_new(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioAccept_new");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio->init = 0;
    bio->num = WOLFSSL_SOCKET_INVALID;
    bio->flags = 0;

    bio->ptr = (WOLFCRYPT_BIO_ACCEPT *)
    XMALLOC(sizeof(WOLFCRYPT_BIO_ACCEPT), 0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL)
        return 0;

    XMEMSET(bio->ptr, 0, sizeof(WOLFCRYPT_BIO_ACCEPT));

    ((WOLFCRYPT_BIO_ACCEPT *)bio->ptr)->accept_sock = WOLFSSL_SOCKET_INVALID;
    ((WOLFCRYPT_BIO_ACCEPT *)bio->ptr)->bind_mode = BIO_BIND_NORMAL;
    ((WOLFCRYPT_BIO_ACCEPT *)bio->ptr)->options = 0;
    ((WOLFCRYPT_BIO_ACCEPT *)bio->ptr)->state = ACPT_S_BEFORE;

    bio->shutdown = 1;

    return 1;
}

static void wc_BioAccept_close_socket(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_ACCEPT *baccept;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return;
    }

    baccept = (WOLFCRYPT_BIO_ACCEPT *)bio->ptr;
    if (baccept->accept_sock != WOLFSSL_SOCKET_INVALID) {
        shutdown(baccept->accept_sock, SHUT_RDWR);
#ifdef USE_WINDOWS_API
        closesocket(baccept->accept_sock);
#else
        close(baccept->accept_sock);
#endif
        baccept->accept_sock = WOLFSSL_SOCKET_INVALID;
        bio->num = WOLFSSL_SOCKET_INVALID;
    }
}

static int wc_BioAccept_free(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioAccept_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (!bio->shutdown)
        return 1;

    wc_BioAccept_close_socket(bio);

    if (bio->ptr != NULL) {
        WOLFCRYPT_BIO_ACCEPT *baccept = (WOLFCRYPT_BIO_ACCEPT *)bio->ptr;

        if (baccept->param_addr != NULL)
            XFREE(baccept->param_addr, 0, DYNAMIC_TYPE_OPENSSL);
        if (baccept->ip_port != NULL)
            XFREE(baccept->ip_port, 0, DYNAMIC_TYPE_OPENSSL);
        if (baccept->bio_chain != NULL)
            wc_BioFree(baccept->bio_chain);

        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
        bio->ptr = NULL;
    }

    bio->flags = 0;
    bio->init = 0;

    return 1;
}

static int wc_BioAccept_state(WOLFCRYPT_BIO *bio, WOLFCRYPT_BIO_ACCEPT *baccept)
{
    WOLFCRYPT_BIO *nbio = NULL;
    int s = -1;
    int dsock;

    if (bio == NULL || baccept == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

again:
    switch (baccept->state) {
        case ACPT_S_BEFORE:
            if (baccept->param_addr == NULL) {
                WOLFSSL_ERROR(BIO_NO_PORT_E);
                return -1;
            }

            s = wc_BioGetAcceptSocket(baccept->param_addr, baccept->bind_mode);
            if (s == WOLFSSL_SOCKET_INVALID)
                return -1;

            if (baccept->accept_nbio) {
                if (!wc_BioSocketNbio(s, 1)) {
#ifdef USE_WINDOWS_API
                    closesocket(s);
#else
                    close(s);
#endif
                    WOLFSSL_ERROR(BIO_NBIO_E);
                    return -1;
                }
            }

            /* TCP NO DELAY */
            if (baccept->options & BIO_OPT_TCP_NO_DELAY) {
                if (!wc_BioSetTcpNdelay(s, 1)) {
#ifdef USE_WINDOWS_API
                    closesocket(s);
#else
                    close(s);
#endif
                    WOLFSSL_ERROR(BIO_OPTIONS_E);
                    return -1;
                }
            }

            /* IGNORE SIGPIPE */
            if (baccept->options & BIO_OPT_IGN_SIGPIPE) {
                if (!wc_BioSetTcpNsigpipe(s, 1)) {
#ifdef USE_WINDOWS_API
                    closesocket(s);
#else
                    close(s);
#endif
                    WOLFSSL_ERROR(BIO_OPTIONS_E);
                    return -1;
                }
            }

            baccept->accept_sock = s;
            bio->num = s;
            baccept->state = ACPT_S_GET_ACCEPT_SOCKET;
            return 1;
            break;

        case ACPT_S_GET_ACCEPT_SOCKET:
            if (bio->next_bio != NULL) {
                baccept->state = ACPT_S_OK;
                goto again;
            }

            wc_BioClearRetryFlags(bio);
            bio->retry_reason = 0;
            dsock = wc_BioAccept(baccept->accept_sock, &baccept->ip_port);

            /* retry case */
            if (dsock == -2) {
                wc_BioSetRetrySpecial(bio);
                bio->retry_reason = BIO_RR_ACCEPT;
                return -1;
            }

            if (dsock < 0)
                return dsock;

            nbio = wc_BioNewSocket(dsock, BIO_CLOSE);
            if (nbio == NULL)
                goto err;

            wc_BioSetCallback(nbio, wc_BioGetCallback(bio));
            wc_BioSetCallbackArg(nbio, wc_BioGetCallbackArg(bio));

            if (baccept->nbio) {
                if (!wc_BioSocketNbio(dsock, 1)) {
                    WOLFSSL_ERROR(BIO_NBIO_E);
                    goto err;
                }
            }

            /*
             * If the accept BIO has an bio_chain, we dup it and put the new
             * socket at the end.
             */
            if (baccept->bio_chain != NULL) {
                WOLFCRYPT_BIO *dbio = wc_BioDupChain(baccept->bio_chain);
                if (dbio == NULL)
                    goto err;
                if (!wc_BioPush(dbio, nbio))
                    goto err;
                nbio = dbio;
            }

            if (wc_BioPush(bio, nbio) == NULL)
                goto err;

            baccept->state = ACPT_S_OK;
            return 1;
        err:
            if (nbio != NULL)
                wc_BioFree(nbio);
            else if (s >= 0)
#ifdef USE_WINDOWS_API
                closesocket(s);
#else
            close(s);
#endif
            break;

        case ACPT_S_OK:
            if (bio->next_bio == NULL) {
                baccept->state = ACPT_S_GET_ACCEPT_SOCKET;
                goto again;
            }
            return 1;
            break;

        default:
            break;
    }

    return 0;
}

static int wc_BioAccept_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 0;
    WOLFCRYPT_BIO_ACCEPT *baccept;

    if (bio == NULL || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    wc_BioClearRetryFlags(bio);
    baccept = (WOLFCRYPT_BIO_ACCEPT *)bio->ptr;

    while (bio->next_bio == NULL) {
        ret = wc_BioAccept_state(bio, baccept);
        if (ret <= 0)
            return ret;
    }

    ret = wc_BioRead(bio->next_bio, data, size);
    wc_BioCopyNextRetry(bio);

    return ret;
}

static int wc_BioAccept_write(WOLFCRYPT_BIO *bio, const char *data, int size)
{
    int ret = 0;
    WOLFCRYPT_BIO_ACCEPT *baccept;

    if (bio == NULL || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    wc_BioClearRetryFlags(bio);
    baccept = (WOLFCRYPT_BIO_ACCEPT *)bio->ptr;

    while (bio->next_bio == NULL) {
        ret = wc_BioAccept_state(bio, baccept);
        if (ret <= 0)
            return ret;
    }

    ret = wc_BioWrite(bio->next_bio, data, size);
    wc_BioCopyNextRetry(bio);

    return ret;
}

static long wc_BioAccept_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{
    int *ip;
    long ret = 1;
    WOLFCRYPT_BIO_ACCEPT *baccept;
    char **pp;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    baccept = (WOLFCRYPT_BIO_ACCEPT *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            ret = 0;
            baccept->state = ACPT_S_BEFORE;
            wc_BioAccept_close_socket(bio);
            bio->flags = 0;
            break;

        case BIO_C_DO_STATE_MACHINE:
            /* use this one to start the connection */
            ret = (long)wc_BioAccept_state(bio, baccept);
            break;

        case BIO_C_SET_ACCEPT:
            if (ptr != NULL) {
                if (num == 0) {
                    bio->init = 1;
                    if (baccept->param_addr != NULL)
                        XFREE(baccept->param_addr, 0, DYNAMIC_TYPE_OPENSSL);
                    baccept->param_addr = strdup(ptr);
                }
                else if (num == 1) {
                    baccept->accept_nbio = (ptr != NULL);
                }
                else if (num == 2) {
                    if (baccept->bio_chain != NULL)
                        wc_BioFree(baccept->bio_chain);
                    baccept->bio_chain = (WOLFCRYPT_BIO *)ptr;
                }
            }
            break;

        case BIO_C_SET_NBIO:
            baccept->nbio = (int)num;
            break;

        case BIO_C_SET_FD:
            bio->init = 1;
            bio->num = *((int *)ptr);
            baccept->accept_sock = bio->num;
            baccept->state = ACPT_S_GET_ACCEPT_SOCKET;
            bio->shutdown = (int)num;
            bio->init = 1;
            break;

        case BIO_C_GET_FD:
            if (bio->init) {
                ip = (int *)ptr;
                if (ip != NULL)
                    *ip = baccept->accept_sock;
                ret = baccept->accept_sock;
            }
            else
                ret = -1;
            break;

        case BIO_C_GET_ACCEPT:
            if (bio->init) {
                if (ptr != NULL) {
                    pp = (char **)ptr;
                    *pp = baccept->param_addr;
                }
                else
                    ret = -1;
            }
            else
                ret = -1;
            break;

        case BIO_CTRL_GET_CLOSE:
            ret = bio->shutdown;
            break;

        case BIO_CTRL_SET_CLOSE:
            bio->shutdown = (int)num;
            break;

        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
            ret = 0;
            break;

        case BIO_CTRL_FLUSH:
        case BIO_CTRL_DUP:
            break;

        case BIO_C_SET_BIND_MODE:
            baccept->bind_mode = (int)num;
            break;

        case BIO_C_GET_BIND_MODE:
            ret = (long)baccept->bind_mode;
            break;

        case BIO_C_SET_EX_ARG:
            baccept->options = (int)num;
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

static int wc_BioAccept_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }
    
    return wc_BioAccept_write(bio, str, (int)XSTRLEN(str));
}

WOLFCRYPT_BIO *wc_BioNewAccept(const char *str)
{
    WOLFCRYPT_BIO *bio;
    
    if (str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }
    
    bio = wc_BioNew(wc_Bio_s_accept());
    if (bio == NULL)
        return NULL;
    
    if (wc_BioSetAcceptPort(bio, str))
        return bio;
    
    wc_BioFree(bio);
    return NULL;
}

/* end BIO Method accept */

/* start BIO Method connect */

static int wc_BioConn_write(WOLFCRYPT_BIO *bio, const char *data, int size);
static int wc_BioConn_read(WOLFCRYPT_BIO *bio, char *data, int size);
static int wc_BioConn_puts(WOLFCRYPT_BIO *bio, const char *str);
static long wc_BioConn_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioConn_new(WOLFCRYPT_BIO *bio);
static int wc_BioConn_free(WOLFCRYPT_BIO *bio);
static long wc_BioConn_callback_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                                     WOLFCRYPT_BIO_info_cb *fp);

static WOLFCRYPT_BIO_METHOD wc_BioConn_method = {
    BIO_TYPE_SOCKET,
    "Socket connect",
    wc_BioConn_write,
    wc_BioConn_read,
    wc_BioConn_puts,
    NULL, /* gets */
    wc_BioConn_ctrl,
    wc_BioConn_new,
    wc_BioConn_free,
    wc_BioConn_callback_ctrl,
};

typedef struct {
    int state;
    int nbio;

    /* keep received Hostname and Port */
    char *pHostname;
    char *pPort;

    /* internal usage */
    unsigned char ip[4];
    unsigned short port;

    struct sockaddr_in them;

    /*
     * called when the connection is initially made callback(BIO,state,ret);
     * The callback should return 'ret'.  state is for compatibility with the
     * ssl info_callback
     */
    int (*info_callback) (const WOLFCRYPT_BIO *bio, int state, int ret);
} WOLFCRYPT_BIO_CONNECT;

static int wc_BioConn_state(WOLFCRYPT_BIO *bio, WOLFCRYPT_BIO_CONNECT *conn)
{
    int ret = -1, i;
    word32 l;
    char *p, *q;

    WOLFSSL_ENTER("wc_BioConn_state");

    if (bio == NULL || conn == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    for (;;) {
        switch (conn->state) {
            case BIO_CONN_S_BEFORE:
                p = conn->pHostname;
                if (p == NULL) {
                    WOLFSSL_ERROR(BIO_NO_HOSTNAME_E);
                    goto exit_loop;
                }

                for (; *p != '\0'; p++) {
                    if ((*p == ':') || (*p == '/'))
                        break;
                }

                i = *p;
                if ((i == ':') || (i == '/')) {
                    *(p++) = '\0';
                    if (i == ':') {
                        for (q = p; *q; q++)
                            if (*q == '/') {
                                *q = '\0';
                                break;
                            }

                        if (conn->pPort != NULL)
                            XFREE(conn->pPort, 0, DYNAMIC_TYPE_OPENSSL);

                        conn->pPort = XMALLOC(XSTRLEN(p)+1,
                                              0, DYNAMIC_TYPE_OPENSSL);
                        if (conn->pPort == NULL) {
                            WOLFSSL_ERROR(MEMORY_E);
                            goto exit_loop;
                            break;
                        }
                        XSTRNCPY(conn->pPort, p, XSTRLEN(p)+1);
                    }
                }

                if (conn->pPort == NULL) {
                    WOLFSSL_ERROR(BIO_NO_PORT_E);
                    goto exit_loop;
                }

                conn->state = BIO_CONN_S_GET_IP;
                break;

            case BIO_CONN_S_GET_IP:
                if (wc_BioGetHostIp(conn->pHostname, conn->ip) <= 0)
                    goto exit_loop;
                conn->state = BIO_CONN_S_GET_PORT;
                break;

            case BIO_CONN_S_GET_PORT:
                if (conn->pPort == NULL ||
                    wc_BioGetPort(conn->pPort, &conn->port) <= 0)
                    goto exit_loop;
                conn->state = BIO_CONN_S_CREATE_SOCKET;
                break;

            case BIO_CONN_S_CREATE_SOCKET:
                /* now setup address */
                XMEMSET(&conn->them, 0, sizeof(conn->them));
                conn->them.sin_family = AF_INET;
                conn->them.sin_port = htons((unsigned short)conn->port);
                l = ((word32)conn->ip[0] << 24L) |
                ((word32)conn->ip[1] << 16L) |
                ((word32)conn->ip[2] << 8L)  |
                ((word32)conn->ip[3]);
                conn->them.sin_addr.s_addr = htonl(l);
                conn->state = BIO_CONN_S_CREATE_SOCKET;

                ret = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (ret <= 0) {
                    WOLFSSL_ERROR(BIO_CREATE_SOCKET_E);
                    goto exit_loop;
                }

                bio->num = ret;
                conn->state = BIO_CONN_S_NBIO;
                break;

            case BIO_CONN_S_NBIO:
                if (conn->nbio) {
                    if (!wc_BioSocketNbio(bio->num, 1)) {
                        WOLFSSL_ERROR(BIO_NBIO_E);
                        goto exit_loop;
                    }
                }
                conn->state = BIO_CONN_S_CONNECT;

# if defined(SO_KEEPALIVE)
                i = 1;
                i = setsockopt(bio->num, SOL_SOCKET, SO_KEEPALIVE, (char *)&i,
                               sizeof(i));
                if (i < 0) {
                    WOLFSSL_ERROR(BIO_KEEPALIVE_E);
                    goto exit_loop;
                }
# endif
                break;


            case BIO_CONN_S_CONNECT:
                wc_BioClearRetryFlags(bio);
                ret = connect(bio->num, (struct sockaddr *)&conn->them,
                              sizeof(conn->them));

                bio->retry_reason = 0;
                if (ret < 0) {
                    if (wc_BioSockShouldRetry(ret)) {
                        wc_BioSetRetrySpecial(bio);
                        conn->state = BIO_CONN_S_BLOCKED_CONNECT;
                        bio->retry_reason = BIO_RR_CONNECT;
                    }
                    else {
                        WOLFSSL_ERROR(BIO_CONNECT_E);
                    }
                    goto exit_loop;
                }
                else
                    conn->state = BIO_CONN_S_OK;
                break;

            case BIO_CONN_S_BLOCKED_CONNECT:
                i = wc_BioSockError(bio->num);
                if (i != 0) {
                    WOLFSSL_ERROR(BIO_CONNECT_E);
                    ret = 0;
                    goto exit_loop;
                }
                else
                    conn->state = BIO_CONN_S_OK;
                break;

            case BIO_CONN_S_OK:
                ret = 1;
                goto exit_loop;
                break;

            default:
                goto exit_loop;
                break;
        }

        if (conn->info_callback != NULL) {
            ret = conn->info_callback(bio, conn->state, ret);
            if (!ret)
                goto end;
        }
    }

exit_loop:
    if (conn->info_callback != NULL)
        ret = conn->info_callback(bio, conn->state, ret);
end:
    return ret;
}

WOLFCRYPT_BIO_METHOD *wc_Bio_s_connect(void)
{
    WOLFSSL_ENTER("wc_Bio_s_connect");

    return (&wc_BioConn_method);
}

static int wc_BioConn_new(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioConn_new");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio->init = 0;
    bio->flags = 0;
    bio->num = WOLFSSL_SOCKET_INVALID;

    bio->ptr = (WOLFCRYPT_BIO_CONNECT *)XMALLOC(sizeof(WOLFCRYPT_BIO_CONNECT),
                                                0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return 0;
    }

    XMEMSET(bio->ptr, 0, sizeof(WOLFCRYPT_BIO_CONNECT));

    ((WOLFCRYPT_BIO_CONNECT *)bio->ptr)->state = BIO_CONN_S_BEFORE;

    return 1;
}

static void wc_BioConn_close_socket(WOLFCRYPT_BIO *bio)
{
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("wc_BioConn_close_socket");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return ;
    }

    conn = (WOLFCRYPT_BIO_CONNECT *)bio->ptr;

    if (bio->num > 0) {
        /* Only do a shutdown if things were established */
        if (conn->state == BIO_CONN_S_OK)
            shutdown(bio->num, SHUT_RDWR);
#ifdef USE_WINDOWS_API
        closesocket(bio->num);
#else
        close(bio->num);
#endif
        bio->num = WOLFSSL_SOCKET_INVALID;
    }
}

static int wc_BioConn_free(WOLFCRYPT_BIO *bio)
{
    WOLFSSL_ENTER("wc_BioConn_free");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (bio->shutdown) {
        wc_BioConn_close_socket(bio);
        if (bio->ptr != NULL) {
            WOLFCRYPT_BIO_CONNECT *c = (WOLFCRYPT_BIO_CONNECT*)bio->ptr;

            if (c->pHostname != NULL) {
                XFREE(c->pHostname, 0, DYNAMIC_TYPE_OPENSSL);
                c->pHostname = NULL;
            }
            if (c->pPort != NULL) {
                XFREE(c->pPort, 0, DYNAMIC_TYPE_OPENSSL);
                c->pPort = NULL;
            }
            XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);
            bio->ptr = NULL;
        }
        bio->flags = 0;
        bio->init = 0;
    }

    return 1;
}

static int wc_BioConn_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 0;
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("wc_BioConn_read");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    conn = (WOLFCRYPT_BIO_CONNECT *)bio->ptr;
    if (conn->state != BIO_CONN_S_OK) {
        ret = wc_BioConn_state(bio, conn);
        if (ret <= 0)
            return (ret);
    }

#ifdef USE_WINDOWS_API
    WSASetLastError(0);
    ret = (int)recv(bio->num, data, size, 0);
#else
    errno = 0;
    ret = (int)read(bio->num, data, size);
#endif

    wc_BioClearRetryFlags(bio);
    if (ret <= 0) {
        if (wc_BioSockShouldRetry(ret))
            wc_BioSetRetryRead(bio);
    }

    return ret;
}

static int wc_BioConn_write(WOLFCRYPT_BIO *bio, const char *data, int size)
{
    int ret = 0;
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("wc_BioConn_write");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    conn = (WOLFCRYPT_BIO_CONNECT *)bio->ptr;
    if (conn->state != BIO_CONN_S_OK) {
        ret = wc_BioConn_state(bio, conn);
        if (ret <= 0)
            return (ret);
    }

#ifdef USE_WINDOWS_API
    WSASetLastError(0);
    ret = (int)send(bio->num, data, size, 0);
#else
    errno = 0;
    ret = (int)write(bio->num, data, size);
#endif

    wc_BioClearRetryFlags(bio);
    if (ret <= 0) {
        if (wc_BioSockShouldRetry(ret))
            wc_BioSetRetryWrite(bio);
    }

    return ret;
}

static long wc_BioConn_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("wc_BioConn_ctrl");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    conn = (WOLFCRYPT_BIO_CONNECT *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            ret = 0;
            conn->state = BIO_CONN_S_BEFORE;
            wc_BioConn_close_socket(bio);
            bio->flags = 0;
            break;

        case BIO_C_DO_STATE_MACHINE:
            /* use this one to start the connection */
            if (conn->state != BIO_CONN_S_OK)
                ret = (long)wc_BioConn_state(bio, conn);
            else
                ret = 1;
            break;

        case BIO_C_GET_CONNECT:
            if (ptr == NULL)
                break;

            if (num == 0)
                *((const char **)ptr) = conn->pHostname;
            else if (num == 1)
                *((const char **)ptr) = conn->pPort;
            else if (num == 2)
                *((const char **)ptr) = (char *)conn->ip;
            else if (num == 3)
                *((int *)ptr) = conn->port;

            if (!bio->init || ptr == NULL)
                *((const char **)ptr) = "not initialized";

            ret = 1;
            break;

        case BIO_C_SET_CONNECT:
            if (ptr == NULL)
                break;

            bio->init = 1;
            if (num == 0) {
                if (conn->pHostname != NULL)
                    XFREE(conn->pHostname, 0, DYNAMIC_TYPE_OPENSSL);
                conn->pHostname = XMALLOC(XSTRLEN((char *)ptr)+1,
                                          0, DYNAMIC_TYPE_OPENSSL);
                if (conn->pHostname == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    ret = -1;
                    break;
                }
                XSTRNCPY(conn->pHostname, (char *)ptr, XSTRLEN((char *)ptr)+1);
            }
            else if (num == 1) {
                if (conn->pPort != NULL)
                    XFREE(conn->pPort, 0, DYNAMIC_TYPE_OPENSSL);

                conn->pPort = XMALLOC(XSTRLEN((char *)ptr)+1,
                                      0, DYNAMIC_TYPE_OPENSSL);
                if (conn->pPort == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    ret = -1;
                    break;
                }
                XSTRNCPY(conn->pPort, (char *)ptr, XSTRLEN((char *)ptr)+1);
            }
            else if (num == 2) {
                char buf[16];
                unsigned char *p = ptr;
                int idx, res;

                res = wc_BioIntToStr(p[0], buf, sizeof(buf));
                if (res <= 0) {
                    WOLFSSL_ERROR(BAD_FUNC_ARG);
                    ret = -1;
                    break;
                }
                idx = res;
                buf[idx++] = '.';
                res = wc_BioIntToStr(p[1], buf+idx, sizeof(buf)-idx);
                if (res <= 0) {
                    WOLFSSL_ERROR(BAD_FUNC_ARG);
                    ret = -1;
                    break;
                }
                idx += res;
                buf[idx++] = '.';
                res = wc_BioIntToStr(p[2], buf+idx, sizeof(buf)-idx);
                if (res <= 0) {
                    WOLFSSL_ERROR(BAD_FUNC_ARG);
                    ret = -1;
                    break;
                }
                idx += res;
                buf[idx++] = '.';
                res = wc_BioIntToStr(p[3], buf+idx, sizeof(buf)-idx);
                if (res <= 0) {
                    WOLFSSL_ERROR(BAD_FUNC_ARG);
                    ret = -1;
                    break;
                }

                if (conn->pHostname != NULL)
                    XFREE(conn->pHostname, 0, DYNAMIC_TYPE_OPENSSL);

                conn->pHostname = XMALLOC(XSTRLEN(buf)+1,
                                          0, DYNAMIC_TYPE_OPENSSL);
                if (conn->pHostname == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    ret = -1;
                    break;
                }
                XSTRNCPY(conn->pHostname, buf, XSTRLEN(buf)+1);
                XMEMCPY(conn->ip, ptr, 4);
            }
            else if (num == 3) {
                char buf[6];
                int res;

                res = wc_BioIntToStr(*(int *)ptr, buf, sizeof(buf));
                if (res <= 0) {
                    WOLFSSL_ERROR(BAD_FUNC_ARG);
                    ret = -1;
                    break;
                }

                if (conn->pPort != NULL)
                    XFREE(conn->pPort, 0, DYNAMIC_TYPE_OPENSSL);

                conn->pPort = XMALLOC(XSTRLEN(buf)+1,
                                      0, DYNAMIC_TYPE_OPENSSL);
                if (conn->pPort == NULL) {
                    WOLFSSL_ERROR(MEMORY_E);
                    ret = -1;
                    break;
                }
                XSTRNCPY(conn->pPort, buf, XSTRLEN(buf)+1);
                conn->port = *(int *)ptr;
            }
            break;

        case BIO_C_SET_NBIO:
            conn->nbio = (int)num;
            break;

        case BIO_C_GET_FD:
            if (bio->init) {
                if (ptr != NULL)
                    *((int *)ptr) = bio->num;
                ret = bio->num;
            }
            else
                ret = -1;
            break;

        case BIO_CTRL_GET_CLOSE:
            ret = bio->shutdown;
            break;

        case BIO_CTRL_SET_CLOSE:
            bio->shutdown = (int)num;
            break;

        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
            ret = 0;
            break;

        case BIO_CTRL_FLUSH:
            break;

        case BIO_CTRL_DUP:
        {
            WOLFCRYPT_BIO *dbio = (WOLFCRYPT_BIO *)ptr;

            if (conn->pPort != NULL)
                wc_BioSetConnPort(dbio, conn->pPort);

            if (conn->pHostname != NULL)
                wc_BioSetConnHostname(dbio, conn->pHostname);

            wc_BioSetNbio(dbio, conn->nbio);

            (void)wc_BioSetInfoCallback(dbio,
                                  (WOLFCRYPT_BIO_info_cb *)conn->info_callback);
        }
            break;

        case BIO_CTRL_SET_CALLBACK:
            ret = 0;
            break;

        case BIO_CTRL_GET_CALLBACK:
        {
            int (**fptr) (const WOLFCRYPT_BIO *bio, int state, int xret);

            fptr = (int (**)(const WOLFCRYPT_BIO *bio,
                             int state, int xret))ptr;
            *fptr = conn->info_callback;
        }
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

static long wc_BioConn_callback_ctrl(WOLFCRYPT_BIO *bio,
                                     int cmd, WOLFCRYPT_BIO_info_cb *fp)
{
    long ret = 1;
    WOLFCRYPT_BIO_CONNECT *conn;

    WOLFSSL_ENTER("wc_BioConn_callback_ctrl");

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    conn = (WOLFCRYPT_BIO_CONNECT *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_SET_CALLBACK:
            conn->info_callback = (int (*)(const WOLFCRYPT_BIO *, int, int))fp;
            break;
            
        default:
            ret = 0;
            break;
    }
    
    return ret;
}

static int wc_BioConn_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    WOLFSSL_ENTER("wc_BioConn_puts");
    
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }
    
    return wc_BioConn_write(bio, str, (int)XSTRLEN(str));
}

WOLFCRYPT_BIO *wc_BioNewConnect(const char *str)
{
    WOLFCRYPT_BIO *bio;
    
    WOLFSSL_ENTER("wc_BioNewConnect");
    
    if (str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }
    
    bio = wc_BioNew(wc_Bio_s_connect());
    if (bio == NULL)
        return NULL;
    
    if (wc_BioSetConnHostname(bio, str))
        return bio;
    
    wc_BioFree(bio);
    return NULL;
}

/* end BIO Method connect */

/* start BIO Method datagramm */


#if !defined(IP_MTU)
#define IP_MTU 14
#endif

#if !defined(IPPROTO_IPV6)
#define IPPROTO_IPV6 41
#endif

static int wc_BioDgram_write(WOLFCRYPT_BIO *bio, const char *data, int size);
static int wc_BioDgram_read(WOLFCRYPT_BIO *bio, char *data, int size);
static int wc_BioDgram_puts(WOLFCRYPT_BIO *bio, const char *str);
static long wc_BioDgram_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioDgram_new(WOLFCRYPT_BIO *bio);
static int wc_BioDgram_free(WOLFCRYPT_BIO *bio);
static int wc_BioDgram_clear(WOLFCRYPT_BIO *bio);

static int wc_BioDgram_should_retry(int s);

static void get_current_time(struct timeval *t);

static WOLFCRYPT_BIO_METHOD WOLFCRYPT_BIO_dgram_method = {
    BIO_TYPE_DGRAM,
    "Datagram socket",
    wc_BioDgram_write,
    wc_BioDgram_read,
    wc_BioDgram_puts,
    NULL,  /* gets */
    wc_BioDgram_ctrl,
    wc_BioDgram_new,
    wc_BioDgram_free,
    NULL,
};

typedef struct {
    union {
        struct sockaddr sa;
        struct sockaddr_in sa_in;
        struct sockaddr_in6 sa_in6;
    } peer;
    unsigned int connected;
    unsigned int _errno;
    unsigned int mtu;
    struct timeval next_timeout;
    struct timeval socket_timeout;
} WOLFCRYPT_BIO_DATAGRAM;

static int wc_BioDgram_should_retry(int i)
{
    if (!i || i == -1) {
        int ret;
#ifdef USE_WINDOWS_API
        ret = WSAGetLastError();
#else
        ret = errno;
#endif
        return wc_BioSockNonFatalError(ret);
    }

    return 0;
}

static void get_current_time(struct timeval *t)
{
#ifdef USE_WINDOWS_API
    SYSTEMTIME st;
    union {
        unsigned __int64 ul;
        FILETIME ft;
    } now;

    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &now.ft);
    now.ul -= 116444736000000000UI64; /* re-bias to 1/1/1970 */
    t->tv_sec = (long)(now.ul / 10000000);
    t->tv_usec = ((int)(now.ul % 10000000)) / 10;
# else
    gettimeofday(t, NULL);
# endif
}


WOLFCRYPT_BIO_METHOD *wc_Bio_s_datagram(void)
{
    return (&WOLFCRYPT_BIO_dgram_method);
}

WOLFCRYPT_BIO *wc_BioNewDgram(int fd, int close_flag)
{
    WOLFCRYPT_BIO *bio;

    bio = wc_BioNew(wc_Bio_s_datagram());
    if (bio == NULL)
        return NULL;

    wc_BioSetFd(bio, fd, close_flag);
    return bio;
}

static int wc_BioDgram_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    bio->init = 0;
    bio->num = 0;
    bio->flags = 0;

    bio->ptr = XMALLOC(sizeof(WOLFCRYPT_BIO_DATAGRAM), 0, DYNAMIC_TYPE_OPENSSL);
    if (bio->ptr == NULL)
        return 0;

    XMEMSET(bio->ptr, 0, sizeof(WOLFCRYPT_BIO_DATAGRAM));
    return 1;
}

static int wc_BioDgram_free(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (!wc_BioDgram_clear(bio))
        return 0;

    if (bio->ptr != NULL)
        XFREE(bio->ptr, 0, DYNAMIC_TYPE_OPENSSL);

    return 1;
}

static int wc_BioDgram_clear(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (bio->shutdown) {
        if (bio->init) {
            shutdown(bio->num, SHUT_RDWR);
#ifdef USE_WINDOWS_API
            closesocket(bio->num);
#else
            close(bio->num);
#endif
        }
        bio->init = 0;
        bio->flags = 0;
    }

    return 1;
}

static void wc_BioDgram_adjust_rcv_timeout(WOLFCRYPT_BIO *bio)
{
#ifdef SO_RCVTIMEO
    WOLFCRYPT_BIO_DATAGRAM *dgram;

    union {
        size_t s;
        int i;
    } sz = { 0 };

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return;
    }

    dgram = (WOLFCRYPT_BIO_DATAGRAM *)bio->ptr;

    /* Is a timer active? */
    if (dgram->next_timeout.tv_sec > 0 || dgram->next_timeout.tv_usec > 0) {
        struct timeval timenow, timeleft;

        /* Read current socket timeout */
#ifdef USE_WINDOWS_API
        int timeout;

        sz.i = sizeof(timeout);
        if (getsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                       (void *)&timeout, &sz.i) >= 0) {
            dgram->socket_timeout.tv_sec = timeout / 1000;
            dgram->socket_timeout.tv_usec = (timeout % 1000) * 1000;
        }
#else
        sz.i = sizeof(dgram->socket_timeout);
        if (getsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                       &(dgram->socket_timeout), (void *)&sz) >= 0) {
            if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0)
                if (sz.s > sizeof(dgram->socket_timeout))
                    return ;
        }
#endif /* USE_WINDOWS_API */

        /* Get current time */
        get_current_time(&timenow);

        /* Calculate time left until timer expires */
        XMEMCPY(&timeleft, &dgram->next_timeout, sizeof(struct timeval));
        if (timeleft.tv_usec < timenow.tv_usec) {
            timeleft.tv_usec = 1000000 - timenow.tv_usec + timeleft.tv_usec;
            timeleft.tv_sec--;
        }
        else
            timeleft.tv_usec -= timenow.tv_usec;

        if (timeleft.tv_sec < timenow.tv_sec) {
            timeleft.tv_sec = 0;
            timeleft.tv_usec = 1;
        }
        else
            timeleft.tv_sec -= timenow.tv_sec;

        /*
         * Adjust socket timeout if next handhake message timer will expire
         * earlier.
         */
        if ((!dgram->socket_timeout.tv_sec && !dgram->socket_timeout.tv_usec) ||
            (dgram->socket_timeout.tv_sec > timeleft.tv_sec) ||
            (dgram->socket_timeout.tv_sec == timeleft.tv_sec &&
             dgram->socket_timeout.tv_usec >= timeleft.tv_usec)) {
#ifdef USE_WINDOWS_API
                timeout = timeleft.tv_sec * 1000 + timeleft.tv_usec / 1000;
                setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                           (void *)&timeout, sizeof(timeout));
#else
                setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO, &timeleft,
                           sizeof(struct timeval));
#endif /* USE_WINDOWS_API */
            }
    }
#endif /* SO_RCVTIMEO */
}

static void wc_BioDgram_reset_rcv_timeout(WOLFCRYPT_BIO *bio)
{
#if defined(SO_RCVTIMEO)
    WOLFCRYPT_BIO_DATAGRAM *dgram;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return;
    }

    dgram = (WOLFCRYPT_BIO_DATAGRAM *)bio->ptr;

    /* Is a timer active? */
    if (dgram->next_timeout.tv_sec > 0 || dgram->next_timeout.tv_usec > 0) {
#ifdef USE_WINDOWS_API
        int timeout = dgram->socket_timeout.tv_sec * 1000 +
        dgram->socket_timeout.tv_usec / 1000;
        setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                   (void *)&timeout, sizeof(timeout));
#else
        setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO, &(dgram->socket_timeout),
                   sizeof(struct timeval));
#endif
    }
#endif
}

static int wc_BioDgram_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = 0;
    WOLFCRYPT_BIO_DATAGRAM *dgram;

    struct {
        union {
            size_t s;
            int i;
        } len;
        union {
            struct sockaddr sa;
            struct sockaddr_in sa_in;
            struct sockaddr_in6 sa_in6;
        } peer;
    } sa;

    if (bio == NULL || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    dgram = (WOLFCRYPT_BIO_DATAGRAM *)bio->ptr;

    sa.len.s = 0;
    sa.len.i = sizeof(sa.peer);

#ifdef USE_WINDOWS_API
    WSASetLastError(0);
#else
    errno = 0;
#endif

    XMEMSET(&sa.peer, 0, sizeof(sa.peer));

    wc_BioDgram_adjust_rcv_timeout(bio);

    ret = (int)recvfrom(bio->num, data, size, 0, &sa.peer.sa, (void *)&sa.len);
    if (sizeof(sa.len.i) != sizeof(sa.len.s) && sa.len.i == 0) {
        if (sa.len.s > sizeof(sa.peer))
            return 0;

        sa.len.i = (int)sa.len.s;
    }

    if (!dgram->connected && ret >= 0)
        wc_BioCtrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &sa.peer);

    wc_BioClearRetryFlags(bio);
    if (ret < 0) {
        if (wc_BioDgram_should_retry(ret)) {
            wc_BioSetRetryRead(bio);
#ifdef USE_WINDOWS_API
            dgram->_errno = WSAGetLastError();
#else
            dgram->_errno = errno;
#endif
        }
    }

    wc_BioDgram_reset_rcv_timeout(bio);

    return ret;
}

static int wc_BioDgram_write(WOLFCRYPT_BIO *bio,
                             const char *data, int size)
{
    int ret;
    WOLFCRYPT_BIO_DATAGRAM *dgram;

    if (bio == NULL || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    dgram = (WOLFCRYPT_BIO_DATAGRAM *)bio->ptr;

#ifdef USE_WINDOWS_API
    WSASetLastError(0);
#else
    errno = 0;
#endif

    if (dgram->connected)
#ifdef USE_WINDOWS_API
        ret = (int)send(bio->num, data, size, 0);
#else
        ret = (int)write(bio->num, data, size);
#endif
    else {
        int peerlen = sizeof(dgram->peer);

        if (dgram->peer.sa.sa_family == AF_INET)
            peerlen = sizeof(dgram->peer.sa_in);
        else if (dgram->peer.sa.sa_family == AF_INET6)
            peerlen = sizeof(dgram->peer.sa_in6);

        ret = (int)sendto(bio->num, data, size,
                          0, &dgram->peer.sa, peerlen);
    }

    wc_BioClearRetryFlags(bio);

    if (ret <= 0 && wc_BioDgram_should_retry(ret)) {
        wc_BioSetRetryWrite(bio);
#ifdef USE_WINDOWS_API
        dgram->_errno = WSAGetLastError();
#else
        dgram->_errno = errno;
#endif
    }

    return ret;
}

static long wc_BioDgram_get_mtu_overhead(WOLFCRYPT_BIO_DATAGRAM *dgram)
{
    long ret;

    if (dgram == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    switch (dgram->peer.sa.sa_family) {
        case AF_INET:
            ret = 28;
            break;
        case AF_INET6:
            ret = 48;
            break;
        default:
            ret = 28;
            break;
    }

    return ret;
}

static long wc_BioDgram_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;
    struct sockaddr *to = NULL;
    WOLFCRYPT_BIO_DATAGRAM *dgram;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    dgram = (WOLFCRYPT_BIO_DATAGRAM *)bio->ptr;

    switch (cmd) {
        case BIO_CTRL_RESET:
            num = 0;

        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
        case BIO_C_FILE_SEEK:
        case BIO_C_FILE_TELL:
        case BIO_CTRL_INFO:
            ret = 0;
            break;

        case BIO_C_SET_FD:
            wc_BioDgram_clear(bio);
            bio->num = *((int *)ptr);
            bio->shutdown = (int)num;
            bio->init = 1;
            break;

        case BIO_C_GET_FD:
            if (bio->init) {
                if (ptr != NULL)
                    *((int *)ptr) = bio->num;
                ret = bio->num;
            }
            else
                ret = -1;
            break;

        case BIO_CTRL_GET_CLOSE:
            ret = bio->shutdown;
            break;

        case BIO_CTRL_SET_CLOSE:
            bio->shutdown = (int)num;
            break;

        case BIO_CTRL_DUP:
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;

        case BIO_CTRL_DGRAM_CONNECT:
            to = (struct sockaddr *)ptr;
            switch (to->sa_family) {
                case AF_INET:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa_in));
                    break;

                case AF_INET6:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa_in6));
                    break;

                default:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa));
                    break;
            }
            break;

            /* (Linux)kernel sets DF bit on outgoing IP packets */
        case BIO_CTRL_DGRAM_MTU_DISCOVER:
            break;

        case BIO_CTRL_DGRAM_QUERY_MTU:
            ret = 0;
            break;

        case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
            ret = -wc_BioDgram_get_mtu_overhead(dgram);
            switch (dgram->peer.sa.sa_family) {
                case AF_INET:
                    ret += 576;
                    break;

                case AF_INET6:
                    ret += 1280;
                    break;

                default:
                    ret += 576;
                    break;
            }
            break;

        case BIO_CTRL_DGRAM_GET_MTU:
            return dgram->mtu;
            break;

        case BIO_CTRL_DGRAM_SET_MTU:
            dgram->mtu = (int)num;
            ret = num;
            break;

        case BIO_CTRL_DGRAM_SET_CONNECTED:
            to = (struct sockaddr *)ptr;
            if (to != NULL) {
                dgram->connected = 1;
                switch (to->sa_family) {
                    case AF_INET:
                        XMEMCPY(&dgram->peer, to,
                                sizeof(dgram->peer.sa_in));
                        break;

                    case AF_INET6:
                        XMEMCPY(&dgram->peer, to,
                                sizeof(dgram->peer.sa_in6));
                        break;

                    default:
                        XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa));
                        break;
                }
            }
            else {
                dgram->connected = 0;
                XMEMSET(&dgram->peer, 0, sizeof(dgram->peer));
            }
            break;

        case BIO_CTRL_DGRAM_GET_PEER:
            switch (dgram->peer.sa.sa_family) {
                case AF_INET:
                    ret = sizeof(dgram->peer.sa_in);
                    break;

                case AF_INET6:
                    ret = sizeof(dgram->peer.sa_in6);
                    break;

                default:
                    ret = sizeof(dgram->peer.sa);
                    break;
            }

            if (num == 0 || num > ret)
                num = ret;
            XMEMCPY(ptr, &dgram->peer, (ret = num));
            break;

        case BIO_CTRL_DGRAM_SET_PEER:
            to = (struct sockaddr *)ptr;
            switch (to->sa_family) {
                case AF_INET:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa_in));
                    break;

                case AF_INET6:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa_in6));
                    break;

                default:
                    XMEMCPY(&dgram->peer, to, sizeof(dgram->peer.sa));
                    break;
            }
            break;

        case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
            XMEMCPY(&dgram->next_timeout, ptr, sizeof(struct timeval));
            break;

#if defined(SO_RCVTIMEO)
        case BIO_CTRL_DGRAM_SET_RECV_TIMEOUT:
#ifdef USE_WINDOWS_API
        {
            struct timeval *tv = (struct timeval *)ptr;
            int timeout = tv->tv_sec * 1000 + tv->tv_usec / 1000;
            if (setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                           (void *)&timeout, sizeof(timeout)) < 0)
                ret = -1;
        }
#else
            if (setsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO, ptr,
                           sizeof(struct timeval)) < 0)
                ret = -1;
#endif /* USE_WINDOWS_API */
            break;

        case BIO_CTRL_DGRAM_GET_RECV_TIMEOUT:
        {
            union {
                size_t s;
                int i;
            } sz = { 0 };
#ifdef USE_WINDOWS_API
            int timeout;
            struct timeval *tv = (struct timeval *)ptr;

            sz.i = sizeof(timeout);
            if (getsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                           (void *)&timeout, &sz.i) < 0)
                ret = -1;
            else {
                tv->tv_sec = timeout / 1000;
                tv->tv_usec = (timeout % 1000) * 1000;
                ret = sizeof(*tv);
            }
#else
            sz.i = sizeof(struct timeval);
            if (getsockopt(bio->num, SOL_SOCKET, SO_RCVTIMEO,
                           ptr, (void *)&sz) < 0)
                ret = -1;
            else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0) {
                if (sz.s > sizeof(struct timeval))
                    ret = -1;
                else
                    ret = (int)sz.s;
            }
            else
                ret = sz.i;
#endif /* USE_WINDOWS_API */
        }
            break;
# endif /* defined(SO_RCVTIMEO) */

# if defined(SO_SNDTIMEO)
        case BIO_CTRL_DGRAM_SET_SEND_TIMEOUT:
#ifdef USE_WINDOWS_API
        {
            struct timeval *tv = (struct timeval *)ptr;
            int timeout = tv->tv_sec * 1000 + tv->tv_usec / 1000;
            if (setsockopt(bio->num, SOL_SOCKET, SO_SNDTIMEO,
                           (void *)&timeout, sizeof(timeout)) < 0)
                ret = -1;
        }
#else
            if (setsockopt(bio->num, SOL_SOCKET, SO_SNDTIMEO, ptr,
                           sizeof(struct timeval)) < 0)
                ret = -1;
#endif /* USE_WINDOWS_API */
            break;

        case BIO_CTRL_DGRAM_GET_SEND_TIMEOUT:
        {
            union {
                size_t s;
                int i;
            } sz = { 0 };
#ifdef USE_WINDOWS_API
            int timeout;
            struct timeval *tv = (struct timeval *)ptr;

            sz.i = sizeof(timeout);
            if (getsockopt(bio->num, SOL_SOCKET, SO_SNDTIMEO,
                           (void *)&timeout, &sz.i) < 0)
                ret = -1;
            else {
                tv->tv_sec = timeout / 1000;
                tv->tv_usec = (timeout % 1000) * 1000;
                ret = sizeof(*tv);
            }
#else
            sz.i = sizeof(struct timeval);
            if (getsockopt(bio->num, SOL_SOCKET, SO_SNDTIMEO,
                           ptr, (void *)&sz) < 0)
                ret = -1;
            else if (sizeof(sz.s) != sizeof(sz.i) && sz.i == 0) {
                if (sz.s > sizeof(struct timeval))
                    ret = -1;
                else
                    ret = (int)sz.s;
            }
            else
                ret = sz.i;
#endif /* USE_WINDOWS_API */
        }
            break;
#endif /* defined(SO_SNDTIMEO) */

        case BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP:
        case BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP:
#ifdef USE_WINDOWS_API
            if (dgram->_errno == WSAETIMEDOUT)
#else
                if (dgram->_errno == EAGAIN)
#endif
                {
                    ret = 1;
                    dgram->_errno = 0;
                }
                else
                    ret = 0;
            break;

        case BIO_CTRL_DGRAM_SET_DONT_FRAG:
            ret = -1;
            break;

        case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
            ret = wc_BioDgram_get_mtu_overhead(dgram);
            break;

        default:
            ret = 0;
            break;
    }
    
    return ret;
}

static int wc_BioDgram_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }
    
    return wc_BioDgram_write(bio, str, (int)XSTRLEN(str));
}

/* end BIO Method datagramm */

/* start BIO Method file descriptor */


static int wc_BioFd_write(WOLFCRYPT_BIO *bio, const char *buf, int size);
static int wc_BioFd_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int wc_BioFd_puts(WOLFCRYPT_BIO *bio, const char *str);
static int wc_BioFd_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long wc_BioFd_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioFd_new(WOLFCRYPT_BIO *bio);
static int wc_BioFd_free(WOLFCRYPT_BIO *bio);

static WOLFCRYPT_BIO_METHOD wc_BioFd_method = {
    BIO_TYPE_FD,
    "File descriptor",
    wc_BioFd_write,
    wc_BioFd_read,
    wc_BioFd_puts,
    wc_BioFd_gets,
    wc_BioFd_ctrl,
    wc_BioFd_new,
    wc_BioFd_free,
    NULL,
};

/* functions are not implemented as not really used in OpenSSL except for two
 * cases :
 *   * get password giving 'fd file' instead of 'file name'
 *       (see app_get_pass(), apps/apps.c)
 *   * open STDOUT and STDERR by giving fd instead of name
 *       (see main(), crypto/threads/mttest.c)
 */
WOLFCRYPT_BIO_METHOD *wc_Bio_s_fd(void)
{
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return (&wc_BioFd_method);
}

WOLFCRYPT_BIO *wc_BioNewFd(int fd, int close_flag)
{
    (void)fd;
    (void)close_flag;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return NULL;
}

static int wc_BioFd_new(WOLFCRYPT_BIO *bio)
{
    (void)bio;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static int wc_BioFd_free(WOLFCRYPT_BIO *bio)
{
    (void)bio;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static int wc_BioFd_read(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    (void)bio;
    (void)buf;
    (void)size;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static int wc_BioFd_write(WOLFCRYPT_BIO *bio, const char *buf, int size)
{
    (void)bio;
    (void)buf;
    (void)size;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static long wc_BioFd_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{
    (void)bio;
    (void)ptr;
    (void)cmd;
    (void)num;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static int wc_BioFd_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    (void)bio;
    (void)buf;
    (void)size;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

static int wc_BioFd_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    (void)bio;
    (void)str;
    WOLFSSL_ERROR(NOT_COMPILED_IN);
    return -2;
}

/* end BIO Method file descriptor */

/* start BIO Method file */

#ifndef NO_FILESYSTEM

#ifndef XFERROR
#define XFERROR ferror
#endif

#ifndef XFILENO
#define XFILENO fileno
#endif

#if defined(USE_WINDOWS_API)
#ifndef XSETMODE
#define XSETMODE _setmode
#endif
#endif /* USE_WINDOWS_API */

#ifndef XFFLUSH
#define XFFLUSH fflush
#endif

#ifndef XFEOF
#define XFEOF feof
#endif

#ifndef XFGETS
#define XFGETS fgets
#endif

static int wc_BioFile_write(WOLFCRYPT_BIO *bio, const char *buf, int size);
static int wc_BioFile_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int wc_BioFile_puts(WOLFCRYPT_BIO *bio, const char *str);
static int wc_BioFile_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long wc_BioFile_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioFile_new(WOLFCRYPT_BIO *bio);
static int wc_BioFile_free(WOLFCRYPT_BIO *bio);

static WOLFCRYPT_BIO_METHOD wc_BioFile_method = {
    BIO_TYPE_FILE,
    "FILE pointer",
    wc_BioFile_write,
    wc_BioFile_read,
    wc_BioFile_puts,
    wc_BioFile_gets,
    wc_BioFile_ctrl,
    wc_BioFile_new,
    wc_BioFile_free,
    NULL,
};

WOLFCRYPT_BIO *wc_BioNewFile(const char *name, const char *mode)
{
    XFILE f;

    if (name == NULL || mode == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    f = XFOPEN(name, mode);
    if (f == NULL) {
        WOLFSSL_ERROR(BIO_FILE_OPEN_E);
        return NULL;
    }

    return wc_BioNewFp(f, BIO_CLOSE);
}

WOLFCRYPT_BIO *wc_BioNewFp(XFILE f, int close_flag)
{
    WOLFCRYPT_BIO *bio;

    if (f == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    bio = wc_BioNew(wc_Bio_s_file());
    if (bio == NULL)
        return NULL;

    wc_BioSetFp(bio, f, close_flag);

    return bio;
}

WOLFCRYPT_BIO_METHOD *wc_Bio_s_file(void)
{
    return (&wc_BioFile_method);
}

static int wc_BioFile_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->init = 0;
    bio->num = 0;
    bio->ptr = NULL;

    return 1;
}

static int wc_BioFile_free(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL)
        return 0;

    if (!bio->shutdown || !bio->init)
        return 1;

    if (bio->ptr != NULL) {
        XFCLOSE(bio->ptr);
        bio->ptr = NULL;
    }
    bio->init = 0;

    return 1;
}

static int wc_BioFile_read(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    int ret = 0;

    if (bio == NULL || !bio->init || bio->ptr == NULL || buf == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    ret = (int)XFREAD(buf, sizeof(char), size, (FILE *)bio->ptr);
    if (ret == 0 && XFERROR((FILE *)bio->ptr)) {
        WOLFSSL_ERROR(BIO_FILE_READ_E);
        ret = -1;
    }

    return ret;
}

static int wc_BioFile_write(WOLFCRYPT_BIO *bio, const char *buf, int size)
{
    int ret = 0;

    if (bio == NULL || !bio->init || bio->ptr == NULL || buf == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    ret = (int)XFWRITE(buf, sizeof(char), size, (FILE *)bio->ptr);
    if (ret == 0 && XFERROR((FILE *)bio->ptr)) {
        WOLFSSL_ERROR(BIO_FILE_WRITE_E);
        ret = -1;
    }

    return ret;
}

static long wc_BioFile_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;
    char buf[4];

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    switch (cmd) {
        case BIO_C_FILE_SEEK:
        case BIO_CTRL_RESET:
            ret = (long)XFSEEK((FILE *)bio->ptr, num, 0);
            break;

        case BIO_CTRL_EOF:
            ret = (long)XFEOF((FILE *)bio->ptr);
            break;

        case BIO_C_FILE_TELL:
        case BIO_CTRL_INFO:
            XFSEEK((FILE *)bio->ptr, 0, XSEEK_END);
            ret = XFTELL((FILE *)bio->ptr);
            XREWIND((FILE *)bio->ptr);
            break;

        case BIO_C_SET_FILE_PTR:
            wc_BioFile_free(bio);
            bio->shutdown = (int)num & BIO_CLOSE;
            bio->ptr = ptr;
            bio->init = 1;

#ifdef USE_WINDOWS_API
        {
            int fd;

            fd = XFILENO((FILE *)bio->ptr);
            if (num & BIO_FP_TEXT)
                XSETMODE(fd, O_TEXT);
            else
                XSETMODE(fd, O_BINARY);
        }
#endif /* USE_WINDOWS_API */
            break;

        case BIO_C_SET_FILENAME:
            wc_BioFile_free(bio);
            bio->shutdown = (int)num & BIO_CLOSE;
            if (num & BIO_FP_APPEND) {
                if (num & BIO_FP_READ)
                    XSTRNCPY(buf, "a+", sizeof(buf) - 1);
                else
                    XSTRNCPY(buf, "a", sizeof(buf) - 1);
            }
            else if (num & BIO_FP_READ) {
                if (num & BIO_FP_WRITE)
                    XSTRNCPY(buf, "r+", sizeof(buf) - 1);
                else
                    XSTRNCPY(buf, "r", sizeof(buf));
            }
            else if (num & BIO_FP_WRITE)
                XSTRNCPY(buf, "w", sizeof(buf) - 1);
            else {
                WOLFSSL_ERROR(BIO_FILE_MODE_E);
                ret = 0;
                break;
            }

            if (num & BIO_FP_TEXT)
                XSTRNCAT(buf, "t", sizeof(buf) - 1);
            else
                XSTRNCAT(buf, "b", sizeof(buf) - 1);

            bio->ptr = XFOPEN(ptr, buf);
            if (bio->ptr == NULL) {
                WOLFSSL_ERROR(BIO_FILE_OPEN_E);
                ret = 0;
                break;
            }
            bio->init = 1;

            break;

        case BIO_C_GET_FILE_PTR:
            /* the ptr parameter is a FILE ** in this case. */
            if (ptr != NULL)
                *((FILE **)ptr) = (FILE *)bio->ptr;
            break;

        case BIO_CTRL_GET_CLOSE:
            ret = (long)bio->shutdown;
            break;

        case BIO_CTRL_SET_CLOSE:
            bio->shutdown = (int)num;
            break;

        case BIO_CTRL_FLUSH:
            XFFLUSH((FILE *)bio->ptr);
            break;

        case BIO_CTRL_DUP:
            ret = 1;
            break;

        case BIO_CTRL_WPENDING:
        case BIO_CTRL_PENDING:
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

static int wc_BioFile_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    if (bio == NULL || bio->ptr == NULL || buf == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    /* init buffer */
    XMEMSET(buf, 0, size);

    if ((XFGETS(buf, size, (FILE *)bio->ptr) == NULL) &&
        XFERROR((FILE *)bio->ptr)) {
        WOLFSSL_ERROR(BIO_FILE_GETS_E);
        return -1;
    }

    return (int)XSTRLEN(buf);
}

static int wc_BioFile_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || bio->ptr == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }
    
    return wc_BioFile_write(bio, str, (int)XSTRLEN(str));
}

#endif /* NO_FILESYSTEM */

/* end BIO Method file */

/* start BIO Method memory */


/* wolfSSL buffer type */
typedef struct {
    byte*  data;
    word32 length;
} WOLFCRYPT_BUF_MEM;

static WOLFCRYPT_BUF_MEM *wolfCrypt_BufMem_new(void)
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

static void wolfCrypt_BufMem_free(WOLFCRYPT_BUF_MEM *buf)
{
    if (buf == NULL)
        return;

    if (buf->data != NULL) {
        XMEMSET(buf->data, 0, buf->length);
        XFREE(buf->data, 0, DYNAMIC_TYPE_OPENSSL);
    }

    XFREE(buf, 0, DYNAMIC_TYPE_OPENSSL);
}

static int wolfCrypt_BufMem_grow(WOLFCRYPT_BUF_MEM *buf, size_t len)
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

static int wolfCrypt_BufMem_grow_clean(WOLFCRYPT_BUF_MEM *buf, size_t len)
{
    int ret, idx = -1;
    size_t size = 0;

    if (buf == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    if (buf->length >= len) {
        idx = buf->length;
        size = buf->length - len;
    }

    ret = wolfCrypt_BufMem_grow(buf, len);
    if (ret && idx != -1)
        XMEMSET(&buf->data[idx], 0, size);

    return ret;
}


static int wc_BioMem_write(WOLFCRYPT_BIO *bio, const char *buf, int size);
static int wc_BioMem_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int wc_BioMem_puts(WOLFCRYPT_BIO *bio, const char *str);
static int wc_BioMem_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long wc_BioMem_ctrl(WOLFCRYPT_BIO *bio, int cmd,
                           long num, void *ptr);
static int wc_BioMem_new(WOLFCRYPT_BIO *bio);
static int wc_BioMem_free(WOLFCRYPT_BIO *bio);

static WOLFCRYPT_BIO_METHOD wc_BioMem_method = {
    BIO_TYPE_MEM,
    "Memory buffer",
    wc_BioMem_write,
    wc_BioMem_read,
    wc_BioMem_puts,
    wc_BioMem_gets,
    wc_BioMem_ctrl,
    wc_BioMem_new,
    wc_BioMem_free,
    NULL,
};

WOLFCRYPT_BIO *wc_BioNewMemBuf(void *data, int len)
{
    WOLFCRYPT_BIO       *bio;
    size_t              size;

    if (data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return NULL;
    }

    size = (len < 0) ? XSTRLEN((char *)data) : (size_t)len;

    bio = wc_BioNew(wc_Bio_s_mem());
    if (bio == NULL)
        return NULL;

    ((WOLFCRYPT_BUF_MEM *)bio->ptr)->data = (byte*)data;
    ((WOLFCRYPT_BUF_MEM *)bio->ptr)->length = (word32)size;

    bio->flags |= BIO_FLAGS_MEM_RDONLY;
    bio->num = 0;

    return bio;
}

WOLFCRYPT_BIO_METHOD *wc_Bio_s_mem(void)
{
    return (&wc_BioMem_method);
}

static int wc_BioMem_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->ptr = wolfCrypt_BufMem_new();
    if (bio->ptr == NULL)
        return -1;

    bio->shutdown = 1;
    bio->init = 1;
    bio->num = -1;

    return 1;
}

static int wc_BioMem_free(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL)
        return -1;

    if (!bio->shutdown || !bio->init)
        return 1;

    if (bio->ptr != NULL) {
        if (bio->flags & BIO_FLAGS_MEM_RDONLY)
            ((WOLFCRYPT_BUF_MEM *)bio->ptr)->data = NULL;

        wolfCrypt_BufMem_free(bio->ptr);
        bio->ptr = NULL;
    }

    bio->init = 0;
    return 1;
}

static int wc_BioMem_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret = -1;
    WOLFCRYPT_BUF_MEM *wbmptr;

    if (bio == NULL || !bio->init || bio->ptr == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    wc_BioClearRetryFlags(bio);

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
            wc_BioSetRetryRead(bio);
    }

    return ret;
}

static int wc_BioMem_write(WOLFCRYPT_BIO *bio, const char *data, int size)
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

    wc_BioClearRetryFlags(bio);

    wbmptr = (WOLFCRYPT_BUF_MEM *)bio->ptr;
    init_len = wbmptr->length;

    if (wolfCrypt_BufMem_grow_clean(wbmptr, wbmptr->length + size) !=
        (int)(init_len + size))
        return -1;

    XMEMCPY(&(wbmptr->data[init_len]), data, size);

    return size;
}

static long wc_BioMem_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
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
            wc_BioMem_free(bio);
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

static int wc_BioMem_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    WOLFCRYPT_BUF_MEM *wbmptr;
    int i, blen;

    if (bio == NULL || bio->ptr == NULL || buf == NULL || size <= 0) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    wc_BioClearRetryFlags(bio);

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
    
    i = wc_BioMem_read(bio, buf, i);
    if (i > 0)
        buf[i] = '\0';
    
    return i;
}

static int wc_BioMem_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }
    
    return wc_BioMem_write(bio, str, (int)XSTRLEN(str));
}

/* end BIO Method memory */

/* start BIO Method null */

static int wc_BioNull_write(WOLFCRYPT_BIO *bio, const char *buf, int size);
static int wc_BioNull_read(WOLFCRYPT_BIO *bio, char *buf, int size);
static int wc_BioNull_puts(WOLFCRYPT_BIO *bio, const char *str);
static int wc_BioNull_gets(WOLFCRYPT_BIO *bio, char *buf, int size);
static long wc_BioNull_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioNull_new(WOLFCRYPT_BIO *bio);
static int wc_BioNull_free(WOLFCRYPT_BIO *bio);

static WOLFCRYPT_BIO_METHOD wc_BioNull_method = {
    BIO_TYPE_NULL,
    "NULL",
    wc_BioNull_write,
    wc_BioNull_read,
    wc_BioNull_puts,
    wc_BioNull_gets,
    wc_BioNull_ctrl,
    wc_BioNull_new,
    wc_BioNull_free,
    NULL,
};

WOLFCRYPT_BIO_METHOD *wc_Bio_s_null(void)
{
    return (&wc_BioNull_method);
}

static int wc_BioNull_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL)
        return 0;

    bio->init = 1;
    bio->num = 0;
    bio->ptr = NULL;

    return 1;
}

static int wc_BioNull_free(WOLFCRYPT_BIO *bio)
{
    return bio == NULL ? 0 : 1;
}

static int wc_BioNull_read(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    (void)bio;
    (void)buf;
    (void)size;

    return 0;
}

static int wc_BioNull_write(WOLFCRYPT_BIO *bio, const char *buf, int size)
{
    (void)bio;
    (void)buf;

    return size;
}

static long wc_BioNull_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{
    (void)bio;
    (void)ptr;
    (void)num;

    long ret = 1;

    switch (cmd) {
        case BIO_CTRL_RESET:
        case BIO_CTRL_EOF:
        case BIO_CTRL_SET:
        case BIO_CTRL_SET_CLOSE:
        case BIO_CTRL_FLUSH:
        case BIO_CTRL_DUP:
            ret = 1;
            break;
        case BIO_CTRL_GET_CLOSE:
        case BIO_CTRL_INFO:
        case BIO_CTRL_GET:
        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
        default:
            ret = 0;
            break;
    }

    return ret;
}

static int wc_BioNull_gets(WOLFCRYPT_BIO *bio, char *buf, int size)
{
    (void)bio;
    (void)buf;
    (void)size;

    return 0;
}

static int wc_BioNull_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    (void)bio;

    if (str == NULL)
        return 0;
    
    return (int)XSTRLEN(str);
}

/* end BIO Method null */

/* start BIO Method socket */

static int wc_BioSock_write(WOLFCRYPT_BIO *bio, const char *data, int size);
static int wc_BioSock_read(WOLFCRYPT_BIO *bio, char *data, int size);
static int wc_BioSock_puts(WOLFCRYPT_BIO *bio, const char *str);
static long wc_BioSock_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr);
static int wc_BioSock_new(WOLFCRYPT_BIO *bio);
static int wc_BioSock_free(WOLFCRYPT_BIO *bio);

static WOLFCRYPT_BIO_METHOD wc_BioSock_method = {
    BIO_TYPE_SOCKET,
    "Socket",
    wc_BioSock_write,
    wc_BioSock_read,
    wc_BioSock_puts,
    NULL, /* gets */
    wc_BioSock_ctrl,
    wc_BioSock_new,
    wc_BioSock_free,
    NULL,
};

WOLFCRYPT_BIO_METHOD *wc_Bio_s_socket(void)
{
    return (&wc_BioSock_method);
}

WOLFCRYPT_BIO *wc_BioNewSocket(int fd, int close_flag)
{
    WOLFCRYPT_BIO *ret;

    ret = wc_BioNew(wc_Bio_s_socket());
    if (ret == NULL) {
        WOLFSSL_ERROR(MEMORY_E);
        return NULL;
    }

    wc_BioSetFd(ret, fd, close_flag);
    return ret;
}

static int wc_BioSock_new(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    bio->init = 0;
    bio->num = 0; /* used for fd */
    bio->ptr = NULL;
    bio->flags = 0;

    return 1;
}

static int wc_BioSock_free(WOLFCRYPT_BIO *bio)
{
    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return 0;
    }

    if (!bio->shutdown)
        return 1;

    if (bio->init) {
        shutdown(bio->num, SHUT_RDWR);
#ifdef USE_WINDOWS_API
        closesocket(bio->num);
#else
        close(bio->num);
#endif
    }

    bio->init = 0;
    bio->flags = 0;

    return 1;
}

static int wc_BioSock_read(WOLFCRYPT_BIO *bio, char *data, int size)
{
    int ret;

    if (bio == NULL || !bio->init || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

#ifdef USE_WINDOWS_API
    WSASetLastError(0);
    ret = (int)recv(bio->num, data, size, 0);
#else
    errno = 0;
    ret = (int)read(bio->num, data, size);
#endif

    wc_BioClearRetryFlags(bio);
    if (ret <= 0) {
        if (wc_BioSockShouldRetry(ret))
            wc_BioSetRetryRead(bio);
    }

    return ret;
}

static int wc_BioSock_write(WOLFCRYPT_BIO *bio, const char *data, int size)
{
    int ret;

    if (bio == NULL || !bio->init || data == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

#ifdef USE_WINDOWS_API
    WSASetLastError(0);
    ret = (int)send(bio->num, data, size, 0);
#else
    errno = 0;
    ret = (int)write(bio->num, data, size);
#endif

    wc_BioClearRetryFlags(bio);
    if (ret <= 0) {
        if (wc_BioSockShouldRetry(ret))
            wc_BioSetRetryWrite(bio);
    }

    return ret;
}

static long wc_BioSock_ctrl(WOLFCRYPT_BIO *bio, int cmd, long num, void *ptr)
{
    long ret = 1;

    if (bio == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    switch (cmd) {
        case BIO_C_SET_FD:
            wc_BioSock_free(bio);
            bio->num = *((int *)ptr);
            bio->shutdown = (int)num;
            bio->init = 1;
            break;

        case BIO_C_GET_FD:
            if (bio->init) {
                if (ptr != NULL)
                    *((int *)ptr) = bio->num;
                ret = bio->num;
            }
            else
                ret = -1;
            break;

        case BIO_CTRL_GET_CLOSE:
            ret = bio->shutdown;
            break;

        case BIO_CTRL_SET_CLOSE:
            bio->shutdown = (int)num;
            break;

        case BIO_CTRL_DUP:
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

static int wc_BioSock_puts(WOLFCRYPT_BIO *bio, const char *str)
{
    if (bio == NULL || str == NULL) {
        WOLFSSL_ERROR(BAD_FUNC_ARG);
        return -1;
    }

    return wc_BioSock_write(bio, str, (int)XSTRLEN(str));
}

int wc_BioSockNonFatalError(int err)
{
    switch (err) {
#if defined(WSAEWOULDBLOCK)
        case WSAEWOULDBLOCK:
#endif

#ifdef EWOULDBLOCK
#ifdef WSAEWOULDBLOCK
#if WSAEWOULDBLOCK != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
#else
        case EWOULDBLOCK:
#endif
#endif

#if defined(ENOTCONN)
        case ENOTCONN:
#endif

#ifdef EINTR
        case EINTR:
#endif

#ifdef EAGAIN
#if EWOULDBLOCK != EAGAIN
        case EAGAIN:
#endif
#endif

#ifdef EPROTO
        case EPROTO:
#endif

#ifdef EINPROGRESS
        case EINPROGRESS:
#endif

#ifdef EALREADY
        case EALREADY:
#endif
            return 1;
            break;

        default:
            break;
    }

    return 0;
}

int wc_BioSockShouldRetry(int i)
{
    if (!i || i == -1) {
        int ret;
#ifdef USE_WINDOWS_API
        ret = WSAGetLastError();
#else
        ret = errno;
#endif
        return wc_BioSockNonFatalError(ret);
    }
    
    return 0;
}

/* end BIO Method socket */

#endif /* OPENSSL_EXTRA */
