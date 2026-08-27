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
 */

#include <zephyr/ztest.h>
#include <zephyr/kernel.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

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

ZTEST_SUITE(wolfssl_condvar, NULL, NULL, NULL, NULL, NULL);
