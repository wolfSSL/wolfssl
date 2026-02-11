/* async-tls.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include "examples/async/async_tls.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifndef NET_CUSTOM
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

/* ---------------------------------------------------------------------------*/
/* --- Ready file helpers (CI/automation sync) --- */
/* ---------------------------------------------------------------------------*/
#include <stdio.h>
#include <sys/stat.h>
#include <sys/select.h>

static int async_readyfile_exists(const char* path)
{
    struct stat st;
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    return (stat(path, &st) == 0);
}

int async_readyfile_touch(const char* path)
{
    FILE* f;
    if (path == NULL || path[0] == '\0') {
        return -1;
    }
    f = fopen(path, "w");
    if (f == NULL) {
        return -1;
    }
    fclose(f);
    return 0;
}

void async_readyfile_clear(const char* path)
{
    if (path == NULL || path[0] == '\0') {
        return;
    }
    (void)remove(path);
}

int async_readyfile_wait(const char* path, int timeout_ms)
{
    int waited_ms = 0;
    const int step_ms = 50;
    struct timeval tv;

    while (waited_ms < timeout_ms) {
        if (async_readyfile_exists(path)) {
            return 0;
        }
        tv.tv_sec = 0;
        tv.tv_usec = step_ms * 1000;
        (void)select(0, NULL, NULL, NULL, &tv);
        waited_ms += step_ms;
    }

    return -1;
}

/* ---------------------------------------------------------------------------*/
/* --- Default POSIX transport callbacks --- */
/* ---------------------------------------------------------------------------*/
#ifndef NET_CUSTOM
int async_posix_send_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    int fd = (int)(intptr_t)ctx;
    int ret = (int)NET_SEND(fd, buf, sz);
    if (ret >= 0) {
        return ret;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    return WOLFSSL_CBIO_ERR_GENERAL;
}

int async_posix_recv_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    int fd = (int)(intptr_t)ctx;
    int ret = (int)NET_RECV(fd, buf, sz);
    if (ret >= 0) {
        return ret;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    return WOLFSSL_CBIO_ERR_GENERAL;
}

int async_posix_getdevrandom(unsigned char *out, unsigned int sz)
{
    ssize_t ret;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ret = read(fd, out, sz);
    close(fd);
    if (ret != (ssize_t)sz) {
        return -1;
    }
    return 0;
}
#endif /* !NET_CUSTOM */

int posix_getdevrandom(unsigned char *out, unsigned int sz)
{
#ifdef NET_CUSTOM
    return NET_GETDEVRANDOM(out, sz);
#else
    return async_posix_getdevrandom(out, sz);
#endif
}

/* ---------------------------------------------------------------------------*/
/* --- Example Crypto Callback --- */
/* ---------------------------------------------------------------------------*/
#ifdef WOLF_CRYPTO_CB

/* Example custom context for crypto callback */
#ifndef TEST_PEND_COUNT
#define TEST_PEND_COUNT 2
#endif

/* Example crypto dev callback function that calls software version */
/* This is where you would plug-in calls to your own hardware crypto */
int AsyncTlsCryptoCb(int devIdArg, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE); /* bypass HW by default */
    AsyncTlsCryptoCbCtx* myCtx = (AsyncTlsCryptoCbCtx*)ctx;

    if (info == NULL)
        return BAD_FUNC_ARG;

#ifdef DEBUG_CRYPTOCB
    wc_CryptoCb_InfoString(info);
#endif

    if (info->algo_type == WC_ALGO_TYPE_PK) {
#ifdef WOLFSSL_ASYNC_CRYPT
        /* Test pending response */
        if (info->pk.type == WC_PK_TYPE_RSA ||
            info->pk.type == WC_PK_TYPE_EC_KEYGEN ||
            info->pk.type == WC_PK_TYPE_ECDSA_SIGN ||
            info->pk.type == WC_PK_TYPE_ECDSA_VERIFY ||
            info->pk.type == WC_PK_TYPE_ECDH)
        {
            if (myCtx->pendingCount++ < TEST_PEND_COUNT) return WC_PENDING_E;
            myCtx->pendingCount = 0;
        }
#endif

    #ifndef NO_RSA
        if (info->pk.type == WC_PK_TYPE_RSA) {
            /* set devId to invalid, so software is used */
            info->pk.rsa.key->devId = INVALID_DEVID;

            switch (info->pk.rsa.type) {
                case RSA_PUBLIC_ENCRYPT:
                case RSA_PUBLIC_DECRYPT:
                    /* perform software based RSA public op */
                    ret = wc_RsaFunction(
                        info->pk.rsa.in, info->pk.rsa.inLen,
                        info->pk.rsa.out, info->pk.rsa.outLen,
                        info->pk.rsa.type, info->pk.rsa.key, info->pk.rsa.rng);
                    break;
                case RSA_PRIVATE_ENCRYPT:
                case RSA_PRIVATE_DECRYPT:
                    /* perform software based RSA private op */
                    ret = wc_RsaFunction(
                        info->pk.rsa.in, info->pk.rsa.inLen,
                        info->pk.rsa.out, info->pk.rsa.outLen,
                        info->pk.rsa.type, info->pk.rsa.key, info->pk.rsa.rng);
                    break;
            }

            /* reset devId */
            info->pk.rsa.key->devId = devIdArg;
        }
    #endif
    #ifdef HAVE_ECC
        if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
            /* set devId to invalid, so software is used */
            info->pk.eckg.key->devId = INVALID_DEVID;

            ret = wc_ecc_make_key_ex(info->pk.eckg.rng, info->pk.eckg.size,
                info->pk.eckg.key, info->pk.eckg.curveId);

            /* reset devId */
            info->pk.eckg.key->devId = devIdArg;
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
            /* set devId to invalid, so software is used */
            info->pk.eccsign.key->devId = INVALID_DEVID;

            ret = wc_ecc_sign_hash(
                info->pk.eccsign.in, info->pk.eccsign.inlen,
                info->pk.eccsign.out, info->pk.eccsign.outlen,
                info->pk.eccsign.rng, info->pk.eccsign.key);

            /* reset devId */
            info->pk.eccsign.key->devId = devIdArg;
        }
        else if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {
            /* set devId to invalid, so software is used */
            info->pk.eccverify.key->devId = INVALID_DEVID;

            ret = wc_ecc_verify_hash(
                info->pk.eccverify.sig, info->pk.eccverify.siglen,
                info->pk.eccverify.hash, info->pk.eccverify.hashlen,
                info->pk.eccverify.res, info->pk.eccverify.key);

            /* reset devId */
            info->pk.eccverify.key->devId = devIdArg;
        }
        else if (info->pk.type == WC_PK_TYPE_ECDH) {
            /* set devId to invalid, so software is used */
            info->pk.ecdh.private_key->devId = INVALID_DEVID;

            ret = wc_ecc_shared_secret(
                info->pk.ecdh.private_key, info->pk.ecdh.public_key,
                info->pk.ecdh.out, info->pk.ecdh.outlen);

            /* reset devId */
            info->pk.ecdh.private_key->devId = devIdArg;
        }
    #endif /* HAVE_ECC */
    }

    (void)devIdArg;
    (void)myCtx;

    return ret;
}
#endif /* WOLF_CRYPTO_CB */

/* ---------------------------------------------------------------------------*/
/* --- Example PK (Public Key) Callback --- */
/* ---------------------------------------------------------------------------*/
#ifdef HAVE_PK_CALLBACKS

#endif
