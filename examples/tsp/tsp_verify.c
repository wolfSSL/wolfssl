/* tsp_verify.c
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

/* Time-Stamp Protocol (RFC 3161) example: verify a response.
 *
 *   tsp_verify <file> <request.tsq> <response.tsr> <tsa-cert.der>
 *       Verify a response against the data, the request sent and the
 *       trusted TSA certificate.
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
    defined(WOLFSSL_TSP_VERIFIER)

/* Maximum size of a file read into memory: a DER request, response or
 * certificate. Big enough for an RSA-2048 credential and a typical
 * time-stamp token. */
#ifndef WC_TSP_MAX_FILE_SZ
    #define WC_TSP_MAX_FILE_SZ   8192
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

/* Check a response was granted - print the status when not. */
static int tsp_check_granted(const TspResponse* resp)
{
    word32 status = 0;
    const byte* statusText = NULL;
    word32 statusTextSz = 0;
    word32 failInfo = 0;

    wc_TspResponse_GetStatus(resp, &status, &statusText, &statusTextSz,
        &failInfo);
    if ((status == WC_TSP_PKISTATUS_GRANTED) ||
            (status == WC_TSP_PKISTATUS_GRANTED_WITH_MODS)) {
        return 0;
    }

    fprintf(stderr, "time-stamp not granted: status %lu\n",
        (unsigned long)status);
    if (statusText != NULL) {
        fprintf(stderr, "  status text: %.*s\n", (int)statusTextSz,
            statusText);
    }
    if (failInfo != 0) {
        fprintf(stderr, "  failure information: 0x%08lx\n",
            (unsigned long)failInfo);
    }
    return 1;
}

/* Verify a response against the data and the request sent. */
static int tsp_verify(const char* dataFile, const char* reqFile,
    const char* respFile, const char* certFile)
{
    int ret = 1;
    int r;
    TSP_DECL(TspRequest, req, 1);
    TspResponse resp;
    TSP_DECL(TspTstInfo, tst, 1);
    TSP_DECL(byte, reqDer, WC_TSP_MAX_FILE_SZ);
    word32 reqDerSz = 0;
    TSP_DECL(byte, respDer, WC_TSP_MAX_FILE_SZ);
    word32 respDerSz = 0;
    TSP_DECL(byte, cert, WC_TSP_MAX_FILE_SZ);
    word32 certSz = 0;
    byte hash[WC_SHA256_DIGEST_SIZE];
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;

    TSP_ALLOC(TspRequest, req, 1, goto done);
    TSP_ALLOC(TspTstInfo, tst, 1, goto done);
    TSP_ALLOC(byte, reqDer, WC_TSP_MAX_FILE_SZ, goto done);
    TSP_ALLOC(byte, respDer, WC_TSP_MAX_FILE_SZ, goto done);
    TSP_ALLOC(byte, cert, WC_TSP_MAX_FILE_SZ, goto done);

    /* Load the request, response and trusted TSA certificate. */
    if ((tsp_read_file(reqFile, reqDer, WC_TSP_MAX_FILE_SZ, &reqDerSz) != 0) ||
            (tsp_read_file(respFile, respDer, WC_TSP_MAX_FILE_SZ,
                &respDerSz) != 0) ||
            (tsp_read_file(certFile, cert, WC_TSP_MAX_FILE_SZ, &certSz) != 0)) {
        goto done;
    }

    /* Check the request was for this data - hash the data file again. */
    r = wc_TspRequest_Decode(req, reqDer, reqDerSz);
    if (r != 0) {
        fprintf(stderr, "decode request failed: %s\n", wc_GetErrorString(r));
        goto done;
    }
    /* This example only hashes data with SHA-256 - the request must match. */
    r = wc_TspRequest_GetHashType(req, &hashType);
    if (r == 0)
        r = tsp_hash_file(dataFile, hash);
    if ((r != 0) || (hashType != WC_HASH_TYPE_SHA256) ||
            (req->imprint.hashSz != (word32)sizeof(hash)) ||
            (memcmp(req->imprint.hash, hash, sizeof(hash)) != 0)) {
        fprintf(stderr, "request is not for this data\n");
        goto done;
    }

    /* The time-stamp must have been granted. */
    r = wc_TspResponse_Decode(&resp, respDer, respDerSz);
    if (r != 0) {
        fprintf(stderr, "decode response failed: %s\n", wc_GetErrorString(r));
        goto done;
    }
    if (tsp_check_granted(&resp) != 0) {
        goto done;
    }

    /* Verify the token against the trusted TSA certificate - the signer must
     * be that certificate. The certificate is also used to verify tokens that
     * do not include it. */
    r = wc_TspResponse_Verify(&resp, cert, certSz, tst);
    if (r != 0) {
        fprintf(stderr, "token verification failed: %s\n",
            wc_GetErrorString(r));
        goto done;
    }

    /* Check the TSTInfo is for the request - imprint, nonce and policy. */
    r = wc_TspTstInfo_CheckRequest(tst, req);
    if (r != 0) {
        fprintf(stderr, "token does not match request: %s\n",
            wc_GetErrorString(r));
        goto done;
    }

    /* tst references the response's token - use before respDer is freed. */
    printf("Verification: OK\n");
    printf("  Time: %.*s\n", (int)tst->genTimeSz, tst->genTime);
    ret = 0;

done:
    TSP_FREE(req);
    TSP_FREE(tst);
    TSP_FREE(reqDer);
    TSP_FREE(respDer);
    TSP_FREE(cert);
    return ret;
}

int main(int argc, char* argv[])
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s <file> <request.tsq> <response.tsr> "
            "<tsa-cert.der>\n", argv[0]);
        return 1;
    }
    return tsp_verify(argv[1], argv[2], argv[3], argv[4]);
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
