/* test_lms.c
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

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_lms.h>

#if defined(WOLFSSL_HAVE_LMS) && defined(WOLFSSL_WC_LMS) && \
    !defined(WOLFSSL_LMS_VERIFY_ONLY)

#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/lms.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

#define LMS_TEST_PRIV_KEY_FILE "/tmp/wolfssl_test_lms.key"

static int test_lms_write_key(const byte* priv, word32 privSz, void* context)
{
    FILE* f = fopen((const char*)context, "wb");
    if (f == NULL)
        return -1;
    fwrite(priv, 1, privSz, f);
    fclose(f);
    return WC_LMS_RC_SAVED_TO_NV_MEMORY;
}

static int test_lms_read_key(byte* priv, word32 privSz, void* context)
{
    FILE* f = fopen((const char*)context, "rb");
    if (f == NULL)
        return -1;
    if (fread(priv, 1, privSz, f) == 0) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return WC_LMS_RC_READ_TO_MEMORY;
}

/* Helper: init an LMS key with callbacks and L1-H10-W8 params */
static int test_lms_init_key(LmsKey* key, WC_RNG* rng)
{
    int ret;

    ret = wc_LmsKey_Init(key, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

    ret = wc_LmsKey_SetParameters(key, 1, 10, 8);
    if (ret != 0) return ret;

    ret = wc_LmsKey_SetWriteCb(key, test_lms_write_key);
    if (ret != 0) return ret;

    ret = wc_LmsKey_SetReadCb(key, test_lms_read_key);
    if (ret != 0) return ret;

    ret = wc_LmsKey_SetContext(key, (void*)LMS_TEST_PRIV_KEY_FILE);
    if (ret != 0) return ret;

    (void)rng;
    return 0;
}

#endif /* WOLFSSL_HAVE_LMS && WOLFSSL_WC_LMS && !WOLFSSL_LMS_VERIFY_ONLY */

/*
 * Test basic LMS sign/verify with multiple signings.
 * Uses L1-H10-W8 (1024 total signatures, 32-entry leaf cache).
 */
int test_wc_LmsKey_sign_verify(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_LMS) && defined(WOLFSSL_WC_LMS) && \
    !defined(WOLFSSL_LMS_VERIFY_ONLY)
    LmsKey  key;
    WC_RNG  rng;
    byte    msg[] = "test message for LMS signing";
    byte    sig[2048];
    word32  sigSz;
    int     i;
    int     numSigs = 5;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    remove(LMS_TEST_PRIV_KEY_FILE);
    ExpectIntEQ(test_lms_init_key(&key, &rng), 0);
    ExpectIntEQ(wc_LmsKey_MakeKey(&key, &rng), 0);

    for (i = 0; i < numSigs; i++) {
        sigSz = sizeof(sig);
        ExpectIntEQ(wc_LmsKey_Sign(&key, sig, &sigSz, msg, sizeof(msg)), 0);
        ExpectIntEQ(wc_LmsKey_Verify(&key, sig, sigSz, msg, sizeof(msg)), 0);
    }

    wc_LmsKey_Free(&key);
    wc_FreeRng(&rng);
    remove(LMS_TEST_PRIV_KEY_FILE);
#endif
    return EXPECT_RESULT();
}

/*
 * Test LMS key reload after advancing past the leaf cache window.
 *
 * Reproduces a heap-buffer-overflow bug in wc_lms_treehash_init() where the
 * leaf cache write uses (i * hash_len) instead of ((i - leaf->idx) * hash_len).
 * When q > max_cb (default 32), wc_LmsKey_Reload calls wc_hss_init_auth_path
 * which calls wc_lms_treehash_init with q > 0, causing writes past the end of
 * the leaf cache buffer.
 *
 * Reproduction steps:
 *   1. Generate L1-H10-W8 key (cacheBits=5, max_cb=32)
 *   2. Sign 33 times to advance q past the cache window
 *   3. Free the key and reload from persisted state
 *   4. Sign and verify after reload
 *
 * Without the fix: heap-buffer-overflow at wc_lms_impl.c:1965
 * With the fix:    all operations succeed, signatures verify
 */
int test_wc_LmsKey_reload_cache(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_LMS) && defined(WOLFSSL_WC_LMS) && \
    !defined(WOLFSSL_LMS_VERIFY_ONLY)
    LmsKey  key;
    LmsKey  vkey;
    WC_RNG  rng;
    byte    msg[] = "test message for LMS signing";
    byte    sig[2048];
    word32  sigSz;
    byte    pub[64];
    word32  pubSz = sizeof(pub);
    int     i;
    /* Sign 33 times to advance q past the 32-entry cache window. */
    int     preSigs = 33;

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Phase 1: Generate key and sign past cache window */
    remove(LMS_TEST_PRIV_KEY_FILE);
    ExpectIntEQ(test_lms_init_key(&key, &rng), 0);
    ExpectIntEQ(wc_LmsKey_MakeKey(&key, &rng), 0);

    for (i = 0; i < preSigs; i++) {
        sigSz = sizeof(sig);
        ExpectIntEQ(wc_LmsKey_Sign(&key, sig, &sigSz, msg, sizeof(msg)), 0);
    }

    /* Save public key for verification after reload */
    ExpectIntEQ(wc_LmsKey_ExportPubRaw(&key, pub, &pubSz), 0);

    wc_LmsKey_Free(&key);

    /* Phase 2: Reload key — triggers wc_lms_treehash_init with q=33 */
    ExpectIntEQ(test_lms_init_key(&key, &rng), 0);
    ExpectIntEQ(wc_LmsKey_Reload(&key), 0);

    /* Phase 3: Sign after reload and verify with separate verify-only key */
    sigSz = sizeof(sig);
    ExpectIntEQ(wc_LmsKey_Sign(&key, sig, &sigSz, msg, sizeof(msg)), 0);

    ExpectIntEQ(wc_LmsKey_Init(&vkey, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_LmsKey_SetParameters(&vkey, 1, 10, 8), 0);
    ExpectIntEQ(wc_LmsKey_ImportPubRaw(&vkey, pub, pubSz), 0);
    ExpectIntEQ(wc_LmsKey_Verify(&vkey, sig, sigSz, msg, sizeof(msg)), 0);

    wc_LmsKey_Free(&vkey);
    wc_LmsKey_Free(&key);
    wc_FreeRng(&rng);
    remove(LMS_TEST_PRIV_KEY_FILE);
#endif
    return EXPECT_RESULT();
}
