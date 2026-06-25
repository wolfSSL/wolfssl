/* tsp_query.c
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

/* Time-Stamp Protocol (RFC 3161) example: create a request.
 *
 *   tsp_query <file> <request.tsq>
 *       Hash the file with SHA-256 and write a time-stamp request.
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
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WOLFSSL_TSP) && defined(HAVE_PKCS7) && \
    (!defined(NO_RSA) || defined(HAVE_ECC)) && \
    !defined(NO_SHA256) && !defined(WC_NO_RNG) && !defined(NO_FILESYSTEM) && \
    defined(WOLFSSL_TSP_REQUESTER)

/* Number of random bytes in a nonce. */
#define TSP_NUM_SZ   8

/* Maximum size of an encoded time-stamp request - a hash imprint, nonce and
 * a few small fields. */
#ifndef WC_TSP_MAX_REQ_SZ
    #define WC_TSP_MAX_REQ_SZ    512
#endif

/* Size of the buffer used to hash a file a chunk at a time. */
#ifndef WC_TSP_HASH_CHUNK_SZ
    #define WC_TSP_HASH_CHUNK_SZ 256
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

/* Hash a file with SHA-256 a chunk at a time so the whole file need not be
 * held in memory. */
static int tsp_hash_file(const char* name, byte* hash)
{
    int ret = -1;
    FILE* f = NULL;
    TSP_DECL(wc_Sha256, sha, 1);
    TSP_DECL(byte, buf, WC_TSP_HASH_CHUNK_SZ);
    size_t n;

    TSP_ALLOC(wc_Sha256, sha, 1, goto done);
    TSP_ALLOC(byte, buf, WC_TSP_HASH_CHUNK_SZ, goto done);

    f = fopen(name, "rb");
    if (f == NULL) {
        fprintf(stderr, "failed to open %s\n", name);
        goto done;
    }
    if (wc_InitSha256(sha) == 0) {
        ret = 0;
        while ((n = fread(buf, 1, WC_TSP_HASH_CHUNK_SZ, f)) > 0) {
            if (wc_Sha256Update(sha, buf, (word32)n) != 0) {
                ret = -1;
                break;
            }
        }
        if ((ret == 0) && (ferror(f) != 0))
            ret = -1;
        if (ret == 0)
            ret = (wc_Sha256Final(sha, hash) == 0) ? 0 : -1;
        wc_Sha256Free(sha);
    }

done:
    if (f != NULL)
        fclose(f);
    TSP_FREE(sha);
    TSP_FREE(buf);
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

/* Create a time-stamp request for the file. */
static int tsp_query(const char* dataFile, const char* reqFile)
{
    int ret = 1;
    int r;
    WC_RNG rng;
    int rngInit = 0;
    TSP_DECL(TspRequest, req, 1);
    TSP_DECL(byte, enc, WC_TSP_MAX_REQ_SZ);
    word32 encSz = WC_TSP_MAX_REQ_SZ;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte nonce[TSP_NUM_SZ];

    TSP_ALLOC(TspRequest, req, 1, goto done);
    TSP_ALLOC(byte, enc, WC_TSP_MAX_REQ_SZ, goto done);

    /* Hash the data to be time-stamped - the TSA never sees the data. */
    r = wc_TspRequest_Init(req);
    if (r != 0)
        goto done;
    /* Set the message imprint hash algorithm, then its value. */
    r = wc_TspRequest_SetHashType(req, WC_HASH_TYPE_SHA256);
    if (r != 0)
        goto done;
    if (tsp_hash_file(dataFile, hash) != 0)
        goto done;
    r = wc_TspRequest_SetHash(req, hash, (word32)sizeof(hash));
    if (r != 0)
        goto done;

    /* Random nonce to tie the response to this request - SetNonce strips
     * any leading zero bytes so the nonce is encodable. */
    if (wc_InitRng(&rng) != 0)
        goto done;
    rngInit = 1;
    if (wc_RNG_GenerateBlock(&rng, nonce, (word32)sizeof(nonce)) != 0)
        goto done;
    r = wc_TspRequest_SetNonce(req, nonce, (word32)sizeof(nonce));
    if (r != 0)
        goto done;
    /* Ask for the TSA's certificate to be included in the token. */
    req->certReq = 1;

    r = wc_TspRequest_Encode(req, enc, &encSz);
    if (r != 0) {
        fprintf(stderr, "encode request failed: %s\n", wc_GetErrorString(r));
        goto done;
    }
    if (tsp_write_file(reqFile, enc, encSz) != 0)
        goto done;
    printf("Wrote %u byte time-stamp request to %s\n", encSz, reqFile);
    ret = 0;

done:
    if (rngInit)
        wc_FreeRng(&rng);
    TSP_FREE(req);
    TSP_FREE(enc);
    return ret;
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <file> <request.tsq>\n", argv[0]);
        return 1;
    }
    return tsp_query(argv[1], argv[2]);
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
