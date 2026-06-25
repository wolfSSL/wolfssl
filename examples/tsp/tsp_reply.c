/* tsp_reply.c
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

/* Time-Stamp Protocol (RFC 3161) example: act as a TSA and reply.
 *
 *   tsp_reply <request.tsq> <tsa-cert.der> <tsa-key.der> <response.tsr>
 *            [rsa|ecc]
 *       Write a signed response for the request.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/tsp.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && \
    (!defined(NO_RSA) || defined(HAVE_ECC)) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && !defined(NO_FILESYSTEM) && \
    defined(WOLFSSL_TSP_RESPONDER)

/* TSA policy of this example: 1.3.6.1.4.1.999.1. */
static const byte tsaPolicy[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x87, 0x67, 0x01
};

/* Number of random bytes in a serial number. */
#define TSP_NUM_SZ   8

/* Maximum size of a file read into memory: a DER request, certificate or key,
 * and the time-stamp token written. Big enough for an RSA-2048 credential and
 * a typical time-stamp token. */
#ifndef WC_TSP_MAX_FILE_SZ
    #define WC_TSP_MAX_FILE_SZ   8192
#endif

/* Local variables larger than 63 bytes - big buffers and big structures - are
 * kept off the stack. They are allocated from the heap, unless dynamic memory
 * is not available (WOLFSSL_NO_MALLOC) in which case they go on the stack.
 * WOLFSSL_SMALL_STACK uses the heap path; it never co-exists with
 * WOLFSSL_NO_MALLOC. 'name' is always used as a pointer.
 *
 * TSP_DECL declares, TSP_ALLOC allocates (running 'fail' on failure) and
 * TSP_FREE releases an array of 'cnt' items of 'type' (cnt is 1 for a single
 * object). */
#ifdef WOLFSSL_NO_MALLOC
    #define TSP_DECL(type, name, cnt)            type name[cnt]
    #define TSP_ALLOC(type, name, cnt, fail)     WC_DO_NOTHING
    #define TSP_FREE(name)                       WC_DO_NOTHING
#else
    #define TSP_DECL(type, name, cnt)            type* name = NULL
    #define TSP_ALLOC(type, name, cnt, fail)                                 \
        do {                                                                \
            (name) = (type*)XMALLOC(sizeof(type) * (cnt), NULL,             \
                DYNAMIC_TYPE_TMP_BUFFER);                                   \
            if ((name) == NULL) {                                           \
                fail;                                                       \
            }                                                               \
        } while (0)
    #define TSP_FREE(name)                                                   \
        XFREE((name), NULL, DYNAMIC_TYPE_TMP_BUFFER)
#endif

/* Read a whole file into the caller's buffer. Fails when the file is larger
 * than maxSz so that no dynamic allocation of the file size is needed. */
static int tsp_read_file(const char* name, byte* data, word32 maxSz,
    word32* sz)
{
    int ret = -1;
    FILE* f;
    long len;

    f = fopen(name, "rb");
    if (f == NULL) {
        fprintf(stderr, "failed to open %s\n", name);
        return -1;
    }
    if ((fseek(f, 0, SEEK_END) == 0) && ((len = ftell(f)) >= 0) &&
            (fseek(f, 0, SEEK_SET) == 0)) {
        /* Compare as unsigned long so a length above 4GB is not truncated by
         * a word32 cast to a small value that slips under maxSz. */
        if ((unsigned long)len > maxSz) {
            fprintf(stderr, "%s is too big (%ld > %u)\n", name, len, maxSz);
        }
        else if (fread(data, 1, (size_t)len, f) == (size_t)len) {
            *sz = (word32)len;
            ret = 0;
        }
    }
    fclose(f);
    return ret;
}

/* Write a buffer to a file. */
static int tsp_write_file(const char* name, const byte* data, word32 sz)
{
    int ret = -1;
    FILE* f;

    f = fopen(name, "wb");
    if (f == NULL) {
        fprintf(stderr, "failed to open %s\n", name);
        return -1;
    }
    if (fwrite(data, 1, sz, f) == sz) {
        ret = 0;
    }
    fclose(f);
    return ret;
}

/* Generate a random number without leading zero bytes. */
static int tsp_rand_num(WC_RNG* rng, byte* num, word32 sz, word32* outSz)
{
    word32 i;

    if (wc_RNG_GenerateBlock(rng, num, sz) != 0)
        return -1;
    /* Skip leading zero bytes - keep at least one byte. */
    for (i = 0; (i < sz - 1) && (num[i] == 0x00); i++);
    if (num[i] == 0x00)
        num[i] = 0x01;
    memmove(num, num + i, sz - i);
    *outSz = sz - i;
    return 0;
}

/* Write a response to the file. */
static int tsp_write_response(const char* name, const TspResponse* resp)
{
    int ret = 1;
    int r;
    TSP_DECL(byte, enc, WC_TSP_MAX_FILE_SZ);
    word32 encSz = WC_TSP_MAX_FILE_SZ;

    TSP_ALLOC(byte, enc, WC_TSP_MAX_FILE_SZ, return 1);

    r = wc_TspResponse_Encode(resp, enc, &encSz);
    if (r != 0) {
        fprintf(stderr, "encode response failed: %s\n", wc_GetErrorString(r));
        goto done;
    }
    if (tsp_write_file(name, enc, encSz) != 0)
        goto done;
    printf("Wrote %u byte time-stamp response to %s\n", encSz, name);
    ret = 0;

done:
    TSP_FREE(enc);
    return ret;
}

/* Write a rejection response with failure information. */
static int tsp_reject(const char* name, word32 failInfo, const char* text)
{
    TspResponse resp;

    (void)wc_TspResponse_Init(&resp);
    (void)wc_TspResponse_SetStatus(&resp, WC_TSP_PKISTATUS_REJECTION,
        (const byte*)text, (word32)strlen(text), failInfo);

    printf("Rejecting request: %s\n", text);
    return tsp_write_response(name, &resp);
}

/* Act as a TSA - create a response for the request. */
static int tsp_reply(const char* reqFile, const char* certFile,
    const char* keyFile, const char* respFile, const char* keyType)
{
    int ret = 1;
    int r;
    WC_RNG rng;
    int rngInit = 0;
    TSP_DECL(TspRequest, req, 1);
    TSP_DECL(TspTstInfo, tst, 1);
    TspResponse resp;
    TSP_DECL(byte, reqDer, WC_TSP_MAX_FILE_SZ);
    word32 reqDerSz = 0;
    TSP_DECL(byte, cert, WC_TSP_MAX_FILE_SZ);
    word32 certSz = 0;
    TSP_DECL(byte, key, WC_TSP_MAX_FILE_SZ);
    word32 keySz = 0;
    byte serial[TSP_NUM_SZ];
    word32 serialSz = 0;
    TSP_DECL(byte, token, WC_TSP_MAX_FILE_SZ);
    word32 tokenSz = WC_TSP_MAX_FILE_SZ;

    TSP_ALLOC(TspRequest, req, 1, goto done);
    TSP_ALLOC(TspTstInfo, tst, 1, goto done);
    TSP_ALLOC(byte, reqDer, WC_TSP_MAX_FILE_SZ, goto done);
    TSP_ALLOC(byte, cert, WC_TSP_MAX_FILE_SZ, goto done);
    TSP_ALLOC(byte, key, WC_TSP_MAX_FILE_SZ, goto done);
    TSP_ALLOC(byte, token, WC_TSP_MAX_FILE_SZ, goto done);

    /* Load the request and the TSA's credentials. */
    if ((tsp_read_file(reqFile, reqDer, WC_TSP_MAX_FILE_SZ, &reqDerSz) != 0) ||
            (tsp_read_file(certFile, cert, WC_TSP_MAX_FILE_SZ, &certSz) != 0) ||
            (tsp_read_file(keyFile, key, WC_TSP_MAX_FILE_SZ, &keySz) != 0)) {
        goto done;
    }

    /* A request that does not parse is rejected. */
    r = wc_TspRequest_Decode(req, reqDer, reqDerSz);
    if (r != 0) {
        ret = tsp_reject(respFile, WC_TSP_FAIL_BAD_DATA_FORMAT,
            "request could not be parsed");
        goto done;
    }
    /* The hash algorithm of the imprint must be one the TSA supports. */
    if (wc_HashGetDigestSize(wc_OidGetHash((int)req->imprint.hashAlgOID)) !=
            (int)req->imprint.hashSz) {
        ret = tsp_reject(respFile, WC_TSP_FAIL_BAD_ALG,
            "hash algorithm not supported");
        goto done;
    }

    if (wc_InitRng(&rng) != 0)
        goto done;
    rngInit = 1;

    /* Fill in the TSTInfo for the request. */
    r = wc_TspTstInfo_Init(tst);
    if (r != 0)
        goto done;
    tst->policy = tsaPolicy;
    tst->policySz = (word32)sizeof(tsaPolicy);
    /* Time-stamp the imprint as it was sent. */
    tst->imprint = req->imprint;
    /* Random serial number - a real TSA must ensure uniqueness across
     * restarts. */
    if (tsp_rand_num(&rng, serial, (word32)sizeof(serial), &serialSz) != 0)
        goto done;
    /* Leading zero bytes are stripped so the serial number encodes. */
    if (wc_TspTstInfo_SetSerial(tst, serial, serialSz) != 0)
        goto done;
    /* genTime of NULL - the current time is used. */
    tst->accuracy.seconds = 1;
    /* The nonce must be returned when it was in the request. */
    if (req->nonceSz != 0) {
        tst->nonce = req->nonce;
        tst->nonceSz = req->nonceSz;
    }

    /* Sign the TSTInfo to make a time-stamp token. This example always
     * includes the TSA's certificate in the token. */
    {
        enum wc_PkType keyPkType;

#ifndef HAVE_ECC
        (void)keyType;
#endif
#ifdef HAVE_ECC
        if ((keyType != NULL) && (strcmp(keyType, "ecc") == 0)) {
            keyPkType = WC_PK_TYPE_ECDSA_SIGN;
        }
        else
#endif
        {
#ifndef NO_RSA
            keyPkType = WC_PK_TYPE_RSA;
#else
            /* RSA not available - fall back to ECC. */
            keyPkType = WC_PK_TYPE_ECDSA_SIGN;
#endif
        }
        r = wc_TspTstInfo_Sign(tst, cert, certSz, key, keySz,
            keyPkType, WC_HASH_TYPE_SHA256, &rng, token, &tokenSz);
    }
    if (r != 0) {
        fprintf(stderr, "create token failed: %s\n", wc_GetErrorString(r));
        goto done;
    }

    /* Put the token in a granted response. */
    r = wc_TspResponse_Init(&resp);
    if (r != 0)
        goto done;
    (void)wc_TspResponse_SetStatus(&resp, WC_TSP_PKISTATUS_GRANTED, NULL, 0, 0);
    resp.token = token;
    resp.tokenSz = tokenSz;
    ret = tsp_write_response(respFile, &resp);

done:
    if (rngInit)
        wc_FreeRng(&rng);
    TSP_FREE(req);
    TSP_FREE(tst);
    TSP_FREE(reqDer);
    TSP_FREE(cert);
    TSP_FREE(key);
    TSP_FREE(token);
    return ret;
}

int main(int argc, char* argv[])
{
    if ((argc != 5) && (argc != 6)) {
        fprintf(stderr, "usage: %s <request.tsq> <tsa-cert.der> "
            "<tsa-key.der> <response.tsr> [rsa|ecc]\n", argv[0]);
        return 1;
    }
    return tsp_reply(argv[1], argv[2], argv[3], argv[4],
        (argc == 6) ? argv[5] : NULL);
}

#else

int main(void)
{
#ifdef NO_FILESYSTEM
    fprintf(stderr, "NO_FILESYSTEM is defined\n");
#else
    fprintf(stderr, "Build wolfSSL with ./configure --enable-tsp\n");
#endif
    return 1;
}

#endif
