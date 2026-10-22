/* test_egd_whitebox.c
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


/* Deterministic EGD response regression tests. The white-box smoke runner
 * builds this against --enable-all and checks its exit status. */
#include <wolfssl/options.h>
#include <wolfssl/internal.h>
#include <unistd.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if !defined(OPENSSL_EXTRA) || !defined(USE_WOLFSSL_IO) || \
    !defined(HAVE_SYS_UN_H) || !defined(HAVE_HASHDRBG) || \
    defined(HAVE_FIPS) || defined(USE_WINDOWS_API) || defined(FREERTOS_TCP)
#error "EGD tests require Unix sockets, OPENSSL_EXTRA and HASHDRBG without FIPS"
#endif

static byte response[512];
static size_t responseLen, offset;
static int chunk, interruptCall, readCalls, requests, reseeds;
static int terminalError;
static void* entropyBuffer;
static size_t wipedLen;
static byte seeded[255];
static word32 seededLen;

static int egd_connect(int fd, const struct sockaddr* addr, socklen_t len)
{
    (void)fd; (void)addr; (void)len;
    return 0;
}

static ssize_t egd_write(int fd, const void* data, size_t len)
{
    const byte* request = (const byte*)data;
    (void)fd;
    if (len != 2 || request[0] != 1)
        return -1;
    requests++;
    return (ssize_t)len;
}

static ssize_t egd_read(int fd, void* data, size_t len)
{
    (void)fd;
    if (readCalls == 0)
        entropyBuffer = data;
    readCalls++;
    if (readCalls == interruptCall) {
        errno = EINTR;
        return -1;
    }
    if (offset == responseLen) {
        errno = terminalError;
        return terminalError ? -1 : 0;
    }
    if (len > (size_t)chunk)
        len = (size_t)chunk;
    if (len > responseLen - offset)
        len = responseLen - offset;
    memcpy(data, response + offset, len);
    offset += len;
    return (ssize_t)len;
}

static int egd_reseed(WC_RNG* rng, const byte* data, word32 len)
{
    (void)rng;
    reseeds++;
    seededLen = len;
    if (len > sizeof(seeded))
        return -1;
    memcpy(seeded, data, len);
    return 0;
}

static void egd_zero(void* data, size_t len)
{
    if (data == entropyBuffer)
        wipedLen = len;
    ForceZero(data, len);
}

/* Compile the real implementation with deterministic transport responses.
 * Socket creation and closing still use the real OS calls. */
#define ForceZero egd_zero
#define connect egd_connect
#define write egd_write
#define read egd_read
#define wc_RNG_DRBG_Reseed egd_reseed
#define wc_RNG_DRBG_Stir egd_reseed
#include <src/ssl.c>
#undef wc_RNG_DRBG_Stir
#undef wc_RNG_DRBG_Reseed
#undef read
#undef write
#undef connect
#undef ForceZero

static int failures;
#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "line %d: %s\n", __LINE__, #expr); \
        failures++; \
    } \
} while (0)

static void reset_case(int fragment, int interrupt, int error)
{
    offset = 0;
    readCalls = requests = reseeds = 0;
    seededLen = 0;
    entropyBuffer = NULL;
    wipedLen = 0;
    chunk = fragment;
    interruptCall = interrupt;
    terminalError = error;
}

static int run_egd(void)
{
    int ret = wolfSSL_RAND_egd("unused");
    CHECK(wipedLen == 256);
    return ret;
}

int main(void)
{
    int i, interrupt;
    CHECK(wolfSSL_Init() == WOLFSSL_SUCCESS);
    response[0] = 255;
    for (i = 1; i < 256; i++)
        response[i] = (byte)i;
    responseLen = 256;

    /* Whole body, fragmented body, interrupted header and interrupted body. */
    for (interrupt = 0; interrupt <= 3; interrupt++) {
        reset_case(interrupt == 0 ? 255 : 3,
            interrupt == 2 ? 1 : (interrupt == 3 ? 3 : 0), 0);
        CHECK(run_egd() == 255);
        CHECK(requests == 1);
        CHECK(reseeds == 1 && seededLen == 255);
        CHECK(memcmp(seeded, response + 1, 255) == 0);
        CHECK(offset == responseLen);
    }

    /* Two successful requests: validate accumulation and preserved data. */
    response[0] = 100;
    memset(response + 1, 0x42, 100);
    response[101] = 155;
    memset(response + 102, 0x73, 155);
    responseLen = 257;
    reset_case(3, 0, 0);
    CHECK(run_egd() == 255);
    CHECK(requests == 2 && reseeds == 1 && seededLen == 255);
    for (i = 0; i < 255; i++)
        CHECK(seeded[i] == (i < 100 ? 0x42 : 0x73));

    /* A body that ends prematurely, with EOF or a read error, must not
     * trigger another request or reseed from incomplete data. */
    response[0] = 32;
    responseLen = 6;
    for (i = 0; i < 3; i++) {
        reset_case(3, 0, i == 0 ? 0 : (i == 1 ? EIO : EAGAIN));
        CHECK(run_egd() == WOLFSSL_FATAL_ERROR);
        CHECK(requests == 1 && reseeds == 0);
    }

    /* No header, no available entropy, and a count exceeding remaining room. */
    responseLen = 0;
    reset_case(3, 0, 0);
    CHECK(run_egd() == WOLFSSL_FATAL_ERROR);
    CHECK(reseeds == 0 && requests == 1);
    response[0] = 0;
    responseLen = 1;
    reset_case(3, 0, 0);
    CHECK(run_egd() == 0);
    CHECK(reseeds == 0 && requests == 1);
    response[0] = 100;
    response[101] = 156;
    responseLen = 102;
    reset_case(3, 0, 0);
    CHECK(run_egd() == WOLFSSL_FATAL_ERROR);
    CHECK(offset == 102 && requests == 2 && reseeds == 0);

    wolfSSL_RAND_Cleanup();
    CHECK(wolfSSL_Cleanup() == WOLFSSL_SUCCESS);
    if (failures == 0)
        puts("PASS: EGD response regression tests");
    return failures ? 1 : 0;
}
