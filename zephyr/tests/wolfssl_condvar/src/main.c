/* main.c
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

/*
 * Exercises wolfCrypt's native Zephyr threading primitives -- the k_condvar
 * backed wolfSSL_Cond* API and wolfSSL_NewThread/wolfSSL_JoinThread -- on a
 * multi-threaded, POSIX-free build (see prj.conf: no CONFIG_POSIX_THREADS /
 * CONFIG_PTHREAD_IPC). Covers the producer/consumer wakeup handshake (the
 * atomic release/re-acquire semantics of wolfSSL_CondWait and signalling under
 * the lock) and the NULL-pointer guards of all six condition-variable calls.
 *
 * Also brings up the wolfCrypt DRBG. Nothing in this image calls wolfSSL_Init()
 * or wolfcrypt_test(), both of which register the DRBG seed callback themselves
 * and so would hide a port that fails to register it; under FIPS v5 the module
 * refuses to seed until it is set, so wc_InitRng() fails unless the
 * APPLICATION-level hook in zephyr_init.c ran. Without a bundle, which is how
 * CI runs it, the same check covers the tree's Zephyr wc_GenerateSeed().
 */

#include <zephyr/ztest.h>
#include <zephyr/kernel.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

static COND_TYPE   g_cond;
static volatile int g_predicate;

/* Publish the predicate under the lock, then wake the waiter. */
static THREAD_RETURN WOLFSSL_THREAD condvar_signaler(void* arg)
{
    (void)arg;

    /* Yield so the consumer generally reaches wolfSSL_CondWait() first. The
     * handshake must still be correct if it does not, because the consumer
     * re-checks the predicate under the lock before each wait. */
    k_msleep(50);

    (void)wolfSSL_CondStart(&g_cond);
    g_predicate = 1;
    (void)wolfSSL_CondSignal(&g_cond);
    (void)wolfSSL_CondEnd(&g_cond);
}

ZTEST(wolfssl_condvar, test_producer_consumer_wakeup)
{
    THREAD_TYPE thread;

    g_predicate = 0;

    zassert_equal(wolfSSL_CondInit(&g_cond), 0, "CondInit");
    zassert_equal(wolfSSL_NewThread(&thread, condvar_signaler, NULL), 0,
                  "NewThread");

    /* wolfSSL_CondWait must atomically release the mutex, block, and
     * re-acquire it on wake; loop guards against spurious wakeups. */
    zassert_equal(wolfSSL_CondStart(&g_cond), 0, "CondStart");
    while (!g_predicate) {
        zassert_equal(wolfSSL_CondWait(&g_cond), 0, "CondWait");
    }
    zassert_equal(g_predicate, 1, "predicate observed set after wake");
    zassert_equal(wolfSSL_CondEnd(&g_cond), 0, "CondEnd");

    zassert_equal(wolfSSL_JoinThread(thread), 0, "JoinThread");
    zassert_equal(wolfSSL_CondFree(&g_cond), 0, "CondFree");
}

ZTEST(wolfssl_condvar, test_null_guards)
{
    zassert_equal(wolfSSL_CondInit(NULL),   BAD_FUNC_ARG, "CondInit NULL");
    zassert_equal(wolfSSL_CondFree(NULL),   BAD_FUNC_ARG, "CondFree NULL");
    zassert_equal(wolfSSL_CondStart(NULL),  BAD_FUNC_ARG, "CondStart NULL");
    zassert_equal(wolfSSL_CondSignal(NULL), BAD_FUNC_ARG, "CondSignal NULL");
    zassert_equal(wolfSSL_CondWait(NULL),   BAD_FUNC_ARG, "CondWait NULL");
    zassert_equal(wolfSSL_CondEnd(NULL),    BAD_FUNC_ARG, "CondEnd NULL");
}

ZTEST(wolfssl_condvar, test_init_rng_at_boot)
{
    WC_RNG rng;
    byte   block[32];
    byte   zero[32];
    int    ret;

    zassert_equal(wolfCrypt_Init(), 0, "wolfCrypt_Init");

    /* Nothing in this image calls wc_SetSeed_Cb(), so under FIPS v5 this is
     * where a missing boot-time registration shows. */
    ret = wc_InitRng(&rng);
    zassert_equal(ret, 0, "wc_InitRng: %d", ret);

    XMEMSET(block, 0, sizeof(block));
    XMEMSET(zero, 0, sizeof(zero));
    ret = wc_RNG_GenerateBlock(&rng, block, sizeof(block));
    zassert_equal(ret, 0, "wc_RNG_GenerateBlock: %d", ret);
    zassert_true(XMEMCMP(block, zero, sizeof(block)) != 0,
                 "generated block is all zero");

    zassert_equal(wc_FreeRng(&rng), 0, "wc_FreeRng");
    zassert_equal(wolfCrypt_Cleanup(), 0, "wolfCrypt_Cleanup");
}

ZTEST_SUITE(wolfssl_condvar, NULL, NULL, NULL, NULL, NULL);
