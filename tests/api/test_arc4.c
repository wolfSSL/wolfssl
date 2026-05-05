/* test_arc4.c
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

#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_arc4.h>

/*
 * Testing wc_Arc4SetKey()
 */
int test_wc_Arc4SetKey(void)
{
    EXPECT_DECLS;
#ifndef NO_RC4
    Arc4 arc;
    const char* key = "\x01\x23\x45\x67\x89\xab\xcd\xef";
    int keyLen = 8;

    ExpectIntEQ(wc_Arc4SetKey(&arc, (byte*)key, (word32)keyLen), 0);
    /* Test bad args. */
    ExpectIntEQ(wc_Arc4SetKey(NULL, (byte*)key, (word32)keyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Arc4SetKey(&arc, NULL      , (word32)keyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Arc4SetKey(&arc, (byte*)key, 0     ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();

} /* END test_wc_Arc4SetKey */

/*
 * Testing wc_Arc4Process for ENC/DEC.
 */
int test_wc_Arc4Process(void)
{
    EXPECT_DECLS;
#ifndef NO_RC4
    Arc4 enc;
    Arc4 dec;
    const char* key = "\x01\x23\x45\x67\x89\xab\xcd\xef";
    int keyLen = 8;
    const char* input = "\x01\x23\x45\x67\x89\xab\xcd\xef";
    byte cipher[8];
    byte plain[8];

    /* Init stack variables */
    XMEMSET(&enc, 0, sizeof(Arc4));
    XMEMSET(&dec, 0, sizeof(Arc4));
    XMEMSET(cipher, 0, sizeof(cipher));
    XMEMSET(plain, 0, sizeof(plain));

    /* Use for async. */
    ExpectIntEQ(wc_Arc4Init(&enc, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Arc4Init(&dec, NULL, INVALID_DEVID), 0);

    ExpectIntEQ(wc_Arc4SetKey(&enc, (byte*)key, (word32)keyLen), 0);
    ExpectIntEQ(wc_Arc4SetKey(&dec, (byte*)key, (word32)keyLen), 0);

    ExpectIntEQ(wc_Arc4Process(&enc, cipher, (byte*)input, (word32)keyLen), 0);
    ExpectIntEQ(wc_Arc4Process(&dec, plain, cipher, (word32)keyLen), 0);
    ExpectIntEQ(XMEMCMP(plain, input, keyLen), 0);

    /* Bad args. */
    ExpectIntEQ(wc_Arc4Process(NULL, plain, cipher, (word32)keyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Arc4Process(&dec, NULL, cipher, (word32)keyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_Arc4Process(&dec, plain, NULL, (word32)keyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_Arc4Free(&enc);
    wc_Arc4Free(&dec);
#endif
    return EXPECT_RESULT();

} /* END test_wc_Arc4Process */


#include <wolfssl/wolfcrypt/random.h>

#define MC_CIPHER_TEST_COUNT 100
#define MC_ARC4_MAX_DATA_SZ  1024
#define MC_ARC4_KEY_SZ       16   /* fixed 128-bit key */

/* Monte Carlo test for ARC4: random key and plaintext each iteration */
int test_wc_Arc4_MonteCarlo(void)
{
    EXPECT_DECLS;
#ifndef NO_RC4
    Arc4 enc, dec;
    WC_RNG rng;
    byte key[MC_ARC4_KEY_SZ];
    word32 plainLen = 0;
    int i;
    WC_DECLARE_VAR(plain,     byte, MC_ARC4_MAX_DATA_SZ, NULL);
    WC_DECLARE_VAR(cipher,    byte, MC_ARC4_MAX_DATA_SZ, NULL);
    WC_DECLARE_VAR(decrypted, byte, MC_ARC4_MAX_DATA_SZ, NULL);

    WC_ALLOC_VAR(plain,     byte, MC_ARC4_MAX_DATA_SZ, NULL);
    WC_ALLOC_VAR(cipher,    byte, MC_ARC4_MAX_DATA_SZ, NULL);
    WC_ALLOC_VAR(decrypted, byte, MC_ARC4_MAX_DATA_SZ, NULL);
#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
    ExpectNotNull(decrypted);
#endif

    XMEMSET(&enc, 0, sizeof(enc));
    XMEMSET(&dec, 0, sizeof(dec));
    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_Arc4Init(&enc, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_Arc4Init(&dec, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (i = 0; i < MC_CIPHER_TEST_COUNT && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, key, sizeof(key)), 0);
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, (byte*)&plainLen,
            sizeof(plainLen)), 0);
        plainLen = (plainLen % MC_ARC4_MAX_DATA_SZ) + 1;
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, plain, plainLen), 0);

        ExpectIntEQ(wc_Arc4SetKey(&enc, key, sizeof(key)), 0);
        ExpectIntEQ(wc_Arc4SetKey(&dec, key, sizeof(key)), 0);
        ExpectIntEQ(wc_Arc4Process(&enc, cipher, plain, plainLen), 0);
        ExpectIntEQ(wc_Arc4Process(&dec, decrypted, cipher, plainLen), 0);
        ExpectBufEQ(decrypted, plain, plainLen);
    }

    wc_Arc4Free(&enc);
    wc_Arc4Free(&dec);
    wc_FreeRng(&rng);
    WC_FREE_VAR(plain,     NULL);
    WC_FREE_VAR(cipher,    NULL);
    WC_FREE_VAR(decrypted, NULL);
#endif
    return EXPECT_RESULT();
}
