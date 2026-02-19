/* test_ossl_rand.c
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

#include <tests/unit.h>

#if defined(__linux__) || defined(__FreeBSD__)
#include <unistd.h>
#include <sys/wait.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/ssl.h>
#ifdef OPENSSL_EXTRA
    #include <wolfssl/openssl/rand.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_ossl_rand.h>


#if defined(OPENSSL_EXTRA) && !defined(WOLFSSL_NO_OPENSSL_RAND_CB)
static int stub_rand_seed(const void *buf, int num)
{
    (void)buf;
    (void)num;

    return 123;
}

static int stub_rand_bytes(unsigned char *buf, int num)
{
    (void)buf;
    (void)num;

    return 456;
}

static byte* was_stub_rand_cleanup_called(void)
{
    static byte was_called = 0;

    return &was_called;
}

static void stub_rand_cleanup(void)
{
    byte* was_called = was_stub_rand_cleanup_called();

    *was_called = 1;

    return;
}

static byte* was_stub_rand_add_called(void)
{
    static byte was_called = 0;

    return &was_called;
}

static int stub_rand_add(const void *buf, int num, double entropy)
{
    byte* was_called = was_stub_rand_add_called();

    (void)buf;
    (void)num;
    (void)entropy;

    *was_called = 1;

    return 0;
}

static int stub_rand_pseudo_bytes(unsigned char *buf, int num)
{
    (void)buf;
    (void)num;

    return 9876;
}

static int stub_rand_status(void)
{
    return 5432;
}
#endif /* OPENSSL_EXTRA && !WOLFSSL_NO_OPENSSL_RAND_CB */

int test_wolfSSL_RAND_set_rand_method(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(WOLFSSL_NO_OPENSSL_RAND_CB)
    RAND_METHOD rand_methods = {NULL, NULL, NULL, NULL, NULL, NULL};
    unsigned char* buf = NULL;
    int num = 0;
    double entropy = 0;
    int ret;
    byte* was_cleanup_called = was_stub_rand_cleanup_called();
    byte* was_add_called = was_stub_rand_add_called();

    ExpectNotNull(buf = (byte*)XMALLOC(32 * sizeof(byte), NULL,
        DYNAMIC_TYPE_TMP_BUFFER));

    ExpectIntNE(wolfSSL_RAND_status(), 5432);
    ExpectIntEQ(*was_cleanup_called, 0);
    RAND_cleanup();
    ExpectIntEQ(*was_cleanup_called, 0);


    rand_methods.seed = &stub_rand_seed;
    rand_methods.bytes = &stub_rand_bytes;
    rand_methods.cleanup = &stub_rand_cleanup;
    rand_methods.add = &stub_rand_add;
    rand_methods.pseudorand = &stub_rand_pseudo_bytes;
    rand_methods.status = &stub_rand_status;

    ExpectIntEQ(RAND_set_rand_method(&rand_methods), WOLFSSL_SUCCESS);
    ExpectIntEQ(RAND_seed(buf, num), 123);
    ExpectIntEQ(RAND_bytes(buf, num), 456);
    ExpectIntEQ(RAND_pseudo_bytes(buf, num), 9876);
    ExpectIntEQ(RAND_status(), 5432);

    ExpectIntEQ(*was_add_called, 0);
    /* The function pointer for RAND_add returns int, but RAND_add itself
     * returns void. */
    RAND_add(buf, num, entropy);
    ExpectIntEQ(*was_add_called, 1);
    was_add_called = 0;
    ExpectIntEQ(*was_cleanup_called, 0);
    RAND_cleanup();
    ExpectIntEQ(*was_cleanup_called, 1);
    *was_cleanup_called = 0;


    ret = RAND_set_rand_method(NULL);
    ExpectIntEQ(ret, WOLFSSL_SUCCESS);
    ExpectIntNE(RAND_status(), 5432);
    ExpectIntEQ(*was_cleanup_called, 0);
    RAND_cleanup();
    ExpectIntEQ(*was_cleanup_called, 0);

    RAND_set_rand_method(NULL);

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* OPENSSL_EXTRA && !WOLFSSL_NO_OPENSSL_RAND_CB */
    return EXPECT_RESULT();
}

int test_wolfSSL_RAND_bytes(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    const int size1 = RNG_MAX_BLOCK_LEN;        /* in bytes */
    const int size2 = RNG_MAX_BLOCK_LEN + 1;    /* in bytes */
    const int size3 = RNG_MAX_BLOCK_LEN * 2;    /* in bytes */
    const int size4 = RNG_MAX_BLOCK_LEN * 4;    /* in bytes */
    int  max_bufsize;
    byte *my_buf = NULL;
#if defined(OPENSSL_EXTRA) && defined(HAVE_GETPID) && !defined(__MINGW64__) && \
    !defined(__MINGW32__)
    byte seed[16] = {0};
    byte randbuf[8] = {0};
    int pipefds[2] = {0};
    pid_t pid = 0;
#endif

    /* sanity check */
    ExpectIntEQ(RAND_bytes(NULL, 16), 0);
    ExpectIntEQ(RAND_bytes(NULL, 0), 0);

    max_bufsize = size4;

    ExpectNotNull(my_buf = (byte*)XMALLOC(max_bufsize * sizeof(byte), HEAP_HINT,
        DYNAMIC_TYPE_TMP_BUFFER));

    ExpectIntEQ(RAND_bytes(my_buf, 0), 1);
    ExpectIntEQ(RAND_bytes(my_buf, -1), 0);

    ExpectNotNull(XMEMSET(my_buf, 0, max_bufsize));
    ExpectIntEQ(RAND_bytes(my_buf, size1), 1);
    ExpectIntEQ(RAND_bytes(my_buf, size2), 1);
    ExpectIntEQ(RAND_bytes(my_buf, size3), 1);
    ExpectIntEQ(RAND_bytes(my_buf, size4), 1);
    XFREE(my_buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

#if defined(OPENSSL_EXTRA) && defined(HAVE_GETPID) && !defined(__MINGW64__) && \
    !defined(__MINGW32__)
    XMEMSET(seed, 0, sizeof(seed));
    RAND_cleanup();

    /* No global methods set. */
    ExpectIntEQ(RAND_seed(seed, sizeof(seed)), 1);

    ExpectIntEQ(pipe(pipefds), 0);
    pid = fork();
    ExpectIntGE(pid, 0);
    if (pid == 0) {
        ssize_t n_written = 0;

        /* Child process. */
        close(pipefds[0]);
        RAND_bytes(randbuf, sizeof(randbuf));
        n_written = write(pipefds[1], randbuf, sizeof(randbuf));
        close(pipefds[1]);
        exit(n_written == sizeof(randbuf) ? 0 : 1);
    }
    else {
        /* Parent process. */
        byte childrand[8] = {0};
        int waitstatus = 0;

        close(pipefds[1]);
        ExpectIntEQ(RAND_bytes(randbuf, sizeof(randbuf)), 1);
        ExpectIntEQ(read(pipefds[0], childrand, sizeof(childrand)),
            sizeof(childrand));
    #ifdef WOLFSSL_NO_GETPID
        ExpectBufEQ(randbuf, childrand, sizeof(randbuf));
    #else
        ExpectBufNE(randbuf, childrand, sizeof(randbuf));
    #endif
        close(pipefds[0]);
        waitpid(pid, &waitstatus, 0);
    }
    RAND_cleanup();
#endif
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_RAND(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    byte seed[16];

    XMEMSET(seed, 0, sizeof(seed));

    /* No global methods set. */
    ExpectIntEQ(RAND_seed(seed, sizeof(seed)), 1);
    ExpectIntEQ(RAND_poll(), 1);
    RAND_cleanup();

    ExpectIntEQ(RAND_egd(NULL), -1);
#ifndef NO_FILESYSTEM
    {
        char fname[100];

        ExpectNotNull(RAND_file_name(fname, (sizeof(fname) - 1)));
        ExpectIntEQ(RAND_write_file(NULL), 0);
    }
#endif
#endif
    return EXPECT_RESULT();
}


#if defined(WC_RNG_SEED_CB) && defined(OPENSSL_EXTRA)
static int wc_DummyGenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    word32 i;
    for (i = 0; i < sz; i++ )
        output[i] = (byte)i;

    (void)os;

    return 0;
}
#endif /* WC_RNG_SEED_CB */


int test_wolfSSL_RAND_poll(void)
{
    EXPECT_DECLS;

#if defined(OPENSSL_EXTRA)
     byte seed[16];
    byte rand1[16];
#ifdef WC_RNG_SEED_CB
    byte rand2[16];
#endif

    XMEMSET(seed, 0, sizeof(seed));
    ExpectIntEQ(RAND_seed(seed, sizeof(seed)), 1);
    ExpectIntEQ(RAND_poll(), 1);
    ExpectIntEQ(RAND_bytes(rand1, 16), 1);
    RAND_cleanup();

#ifdef WC_RNG_SEED_CB
    /* Test with custom seed and poll */
    wc_SetSeed_Cb(wc_DummyGenerateSeed);

    ExpectIntEQ(RAND_seed(seed, sizeof(seed)), 1);
    ExpectIntEQ(RAND_bytes(rand1, 16), 1);
    RAND_cleanup();

    /* test that the same value is generated twice with dummy seed function */
    ExpectIntEQ(RAND_seed(seed, sizeof(seed)), 1);
    ExpectIntEQ(RAND_bytes(rand2, 16), 1);
    ExpectIntEQ(XMEMCMP(rand1, rand2, 16), 0);
    RAND_cleanup();

    /* test that doing a poll is reseeding RNG */
    ExpectIntEQ(RAND_seed(seed, sizeof(seed)), 1);
    ExpectIntEQ(RAND_poll(), 1);
    ExpectIntEQ(RAND_bytes(rand2, 16), 1);
    ExpectIntNE(XMEMCMP(rand1, rand2, 16), 0);

    /* reset the seed function used */
    wc_SetSeed_Cb(WC_GENERATE_SEED_DEFAULT);
#endif
    RAND_cleanup();

    ExpectIntEQ(RAND_egd(NULL), -1);
#endif

    return EXPECT_RESULT();
}

