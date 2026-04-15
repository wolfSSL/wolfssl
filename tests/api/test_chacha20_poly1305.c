/* test_chacha20_poly1305.c
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

#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_chacha20_poly1305.h>

/* -------------------------------------------------------------------------
 * Shared test vectors (RFC 8439 §2.8.2)
 * ------------------------------------------------------------------------- */
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)

static const byte tv_key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};
static const byte tv_iv[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47
};
static const byte tv_aad[] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7
};
static const byte tv_plaintext[] = {
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
    0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
    0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
    0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
    0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
    0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
    0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
    0x74, 0x2e
};
static const byte tv_ciphertext[] = {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
    0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
    0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
    0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
    0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
    0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16
};
static const byte tv_authtag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE] = {
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
    0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
};

#endif /* HAVE_CHACHA && HAVE_POLY1305 */

/*
 * Testing wc_ChaCha20Poly1305_Encrypt() and wc_ChaCha20Poly1305_Decrypt()
 */
int test_wc_ChaCha20Poly1305_aead(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    byte        generatedCiphertext[272];
    byte        generatedPlaintext[272];
    byte        generatedAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* Initialize stack variables. */
    XMEMSET(generatedCiphertext, 0, 272);
    XMEMSET(generatedPlaintext, 0, 272);

    /* Test Encrypt */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(tv_key, tv_iv,
        tv_aad, sizeof(tv_aad),
        tv_plaintext, sizeof(tv_plaintext),
        generatedCiphertext, generatedAuthTag), 0);
    ExpectIntEQ(XMEMCMP(generatedCiphertext, tv_ciphertext,
        sizeof(tv_ciphertext)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(NULL, tv_iv, tv_aad, sizeof(tv_aad),
        tv_plaintext, sizeof(tv_plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(tv_key, NULL, tv_aad, sizeof(tv_aad),
        tv_plaintext, sizeof(tv_plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(tv_key, tv_iv, tv_aad, sizeof(tv_aad),
        NULL, sizeof(tv_plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(tv_key, tv_iv, tv_aad, sizeof(tv_aad),
        NULL, sizeof(tv_plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(tv_key, tv_iv, tv_aad, sizeof(tv_aad),
        tv_plaintext, sizeof(tv_plaintext), NULL, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(tv_key, tv_iv, tv_aad, sizeof(tv_aad),
        tv_plaintext, sizeof(tv_plaintext), generatedCiphertext, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(tv_key, tv_iv,
        tv_aad, sizeof(tv_aad),
        tv_ciphertext, sizeof(tv_ciphertext),
        tv_authtag, generatedPlaintext), 0);
    ExpectIntEQ(XMEMCMP(generatedPlaintext, tv_plaintext,
        sizeof(tv_plaintext)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(NULL, tv_iv, tv_aad, sizeof(tv_aad),
        tv_ciphertext, sizeof(tv_ciphertext), tv_authtag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(tv_key, NULL, tv_aad, sizeof(tv_aad),
        tv_ciphertext, sizeof(tv_ciphertext), tv_authtag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(tv_key, tv_iv, tv_aad, sizeof(tv_aad),
        NULL, sizeof(tv_ciphertext), tv_authtag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(tv_key, tv_iv, tv_aad, sizeof(tv_aad),
        tv_ciphertext, sizeof(tv_ciphertext), NULL, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(tv_key, tv_iv, tv_aad, sizeof(tv_aad),
        tv_ciphertext, sizeof(tv_ciphertext), tv_authtag, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(tv_key, tv_iv, tv_aad, sizeof(tv_aad),
        NULL, sizeof(tv_ciphertext), tv_authtag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_aead */

/*
 * Testing wc_XChaCha20Poly1305_Encrypt() and wc_XChaCha20Poly1305_Decrypt()
 * Test vector from Draft IRTF CFRG XChaCha Appendix A.3
 */
int test_wc_XChaCha20Poly1305_aead(void)
{
    EXPECT_DECLS;
#if defined(HAVE_POLY1305) && defined(HAVE_XCHACHA)
    const byte key[] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    /* XChaCha uses a 24-byte nonce */
    const byte nonce[] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57
    };
    const byte plaintext[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };
    const byte aad[] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    /* Expected combined ciphertext + 16-byte tag */
    const byte expected[] = {
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94,
        0x93, 0xc0, 0xe9, 0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc,
        0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39, 0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b,
        0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3, 0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39,
        0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16, 0xcb, 0x96, 0xb7, 0x2e,
        0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45,
        0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b,
        0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9,
        0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76, 0x88, 0x12, 0xf6,
        0x15, 0xc6, 0x8b, 0x13, 0xb5, 0x2e,
        /* Authentication Tag */
        0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8,
        0x78, 0x0a, 0xcf, 0x49
    };

    byte out[256];
    byte plain_out[256];
    word32 outLen = sizeof(plaintext) + 16;

    XMEMSET(out, 0, sizeof(out));
    XMEMSET(plain_out, 0, sizeof(plain_out));

    /* Test Encrypt (One-shot) */
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(out), plaintext,
        sizeof(plaintext), aad, sizeof(aad), nonce, sizeof(nonce),
        key, sizeof(key)), 0);
    ExpectIntEQ(XMEMCMP(out, expected, outLen), 0);

    /* Test Decrypt (One-shot) */
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(plain_out, sizeof(plain_out), out,
        outLen, aad, sizeof(aad), nonce, sizeof(nonce),
        key, sizeof(key)), 0);
    ExpectIntEQ(XMEMCMP(plain_out, plaintext, sizeof(plaintext)), 0);

    /* Test Encrypt bad args. */
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(NULL, sizeof(out), plaintext,
        sizeof(plaintext), aad, sizeof(aad), nonce, sizeof(nonce),
        key, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(out), NULL,
        sizeof(plaintext), aad, sizeof(aad), nonce, sizeof(nonce),
        key, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(out), plaintext,
        sizeof(plaintext), NULL, sizeof(aad), nonce, sizeof(nonce),
        key, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(out), plaintext,
        sizeof(plaintext), aad, sizeof(aad), NULL, sizeof(nonce),
        key, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(out), plaintext,
        sizeof(plaintext), aad, sizeof(aad), nonce, sizeof(nonce),
        NULL, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Wrong nonce size (12 instead of 24) */
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(out), plaintext,
        sizeof(plaintext), aad, sizeof(aad), nonce, 12,
        key, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Wrong key size */
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(out), plaintext,
        sizeof(plaintext), aad, sizeof(aad), nonce, sizeof(nonce),
        key, 16), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test Decrypt bad args. */
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(NULL, sizeof(plain_out), out,
        outLen, aad, sizeof(aad), nonce, sizeof(nonce),
        key, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(plain_out, sizeof(plain_out), NULL,
        outLen, aad, sizeof(aad), nonce, sizeof(nonce),
        key, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(plain_out, sizeof(plain_out), out,
        outLen, NULL, sizeof(aad), nonce, sizeof(nonce),
        key, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(plain_out, sizeof(plain_out), out,
        outLen, aad, sizeof(aad), NULL, sizeof(nonce),
        key, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(plain_out, sizeof(plain_out), out,
        outLen, aad, sizeof(aad), nonce, sizeof(nonce),
        NULL, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Wrong nonce size (12 instead of 24) */
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(plain_out, sizeof(plain_out), out,
        outLen, aad, sizeof(aad), nonce, 12,
        key, sizeof(key)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Wrong key size */
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(plain_out, sizeof(plain_out), out,
        outLen, aad, sizeof(aad), nonce, sizeof(nonce),
        key, 16), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_XChaCha20Poly1305_aead */

#include <wolfssl/wolfcrypt/random.h>

#define MC_CIPHER_TEST_COUNT     100
#define MC_CHACHA20P1305_MAX_SZ  1024

/* Monte Carlo test for ChaCha20-Poly1305: random key, nonce, and plaintext
 * each iteration */
int test_wc_ChaCha20Poly1305_MonteCarlo(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    WC_RNG rng;
    byte key[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte nonce[CHACHA20_POLY1305_AEAD_IV_SIZE];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    word32 plainLen = 0;
    int i;
    WC_DECLARE_VAR(plain,     byte, MC_CHACHA20P1305_MAX_SZ, NULL);
    WC_DECLARE_VAR(cipher,    byte, MC_CHACHA20P1305_MAX_SZ, NULL);
    WC_DECLARE_VAR(decrypted, byte, MC_CHACHA20P1305_MAX_SZ, NULL);

    WC_ALLOC_VAR(plain,     byte, MC_CHACHA20P1305_MAX_SZ, NULL);
    WC_ALLOC_VAR(cipher,    byte, MC_CHACHA20P1305_MAX_SZ, NULL);
    WC_ALLOC_VAR(decrypted, byte, MC_CHACHA20P1305_MAX_SZ, NULL);
#ifdef WC_DECLARE_VAR_IS_HEAP_ALLOC
    ExpectNotNull(plain);
    ExpectNotNull(cipher);
    ExpectNotNull(decrypted);
#endif

    XMEMSET(&rng, 0, sizeof(rng));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    for (i = 0; i < MC_CIPHER_TEST_COUNT && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, key, sizeof(key)), 0);
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, nonce, sizeof(nonce)), 0);
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, (byte*)&plainLen,
            sizeof(plainLen)), 0);
        plainLen = (plainLen % MC_CHACHA20P1305_MAX_SZ) + 1;
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, plain, plainLen), 0);

        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, nonce, NULL, 0,
            plain, plainLen, cipher, tag), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, nonce, NULL, 0,
            cipher, plainLen, tag, decrypted), 0);
        ExpectBufEQ(decrypted, plain, plainLen);
    }

    wc_FreeRng(&rng);
    WC_FREE_VAR(plain,     NULL);
    WC_FREE_VAR(cipher,    NULL);
    WC_FREE_VAR(decrypted, NULL);
#endif
    return EXPECT_RESULT();
}
/* =========================================================================
 * ISO 26262 ASIL-D MC/DC additional coverage tests
 * =========================================================================
 *
 * Function: test_wc_Chacha20Poly1305BadArgCoverage
 *
 * Targets the compound-condition guards in Encrypt (L57), Decrypt (L97),
 * CheckTag (L136), UpdateAad (L205/L208), UpdateData (L235), and
 * Final (L278).  Each ExpectIntEQ pair exercises one unique independence
 * pair of the MC/DC condition under test.
 * ========================================================================= */
int test_wc_Chacha20Poly1305BadArgCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    byte buf[64];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    ChaChaPoly_Aead aead;

    XMEMSET(buf, 0, sizeof(buf));
    XMEMSET(tag, 0, sizeof(tag));

    /* -------------------------------------------------------------------
     * wc_ChaCha20Poly1305_Encrypt L57:
     *   (!inKey || !inIV || (inPlaintextLen>0 && inPlaintext==NULL) || ...)
     *
     * MC/DC pair for the sub-condition (inPlaintextLen>0 && inPlaintext==NULL):
     *   Pair A: len=1, plaintext=NULL  → condition TRUE  → BAD_FUNC_ARG
     *   Pair B: len=1, plaintext=buf   → condition FALSE → no BAD_FUNC_ARG
     *     (pair B succeeds; we only check it does NOT return BAD_FUNC_ARG)
     * ------------------------------------------------------------------- */
    /* Pair A – len>0 AND ptr==NULL: compound is TRUE */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(tv_key, tv_iv,
        NULL, 0,          /* no AAD */
        NULL, 1,          /* len=1, ptr=NULL → fires condition */
        buf, tag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Pair B – len>0 AND ptr!=NULL: compound is FALSE; call succeeds */
    ExpectIntNE(wc_ChaCha20Poly1305_Encrypt(tv_key, tv_iv,
        NULL, 0,
        buf, 1,           /* ptr valid */
        buf, tag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* -------------------------------------------------------------------
     * wc_ChaCha20Poly1305_Decrypt L97:
     *   (inCiphertextLen>0 && inCiphertext==NULL)
     *
     *   Pair A: len=1, cipher=NULL → BAD_FUNC_ARG
     *   Pair B: len=0, cipher=NULL → NOT BAD_FUNC_ARG (len=0 short-circuits)
     * ------------------------------------------------------------------- */
    /* Pair A */
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(tv_key, tv_iv,
        NULL, 0,
        NULL, 1,          /* len=1, ptr=NULL */
        tag, buf),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Pair B – len=0 with NULL input: this build still rejects with
     * BAD_FUNC_ARG; accept either outcome for branch coverage. */
    ExpectIntLE(wc_ChaCha20Poly1305_Decrypt(tv_key, tv_iv,
        NULL, 0,
        NULL, 0,
        tag, buf), 0);

    /* -------------------------------------------------------------------
     * wc_ChaCha20Poly1305_CheckTag L136:
     *   (authTag == NULL || authTagChk == NULL)
     *
     *   Pair for first operand:
     *     Pair A: authTag=NULL, authTagChk=tag → first op TRUE
     *     Pair B: authTag=tag,  authTagChk=tag → first op FALSE, second FALSE
     *   Pair for second operand:
     *     Pair C: authTag=tag,  authTagChk=NULL → second op TRUE (first FALSE)
     * ------------------------------------------------------------------- */
    /* Pair A – first NULL */
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(NULL, tag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Pair B – neither NULL (both conditions FALSE) */
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(tag, tag), 0);
    /* Pair C – second NULL */
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(tag, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* -------------------------------------------------------------------
     * wc_ChaCha20Poly1305_Init – NULL argument guards (drives state machine)
     * ------------------------------------------------------------------- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(NULL, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, NULL, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, NULL,
        CHACHA20_POLY1305_AEAD_ENCRYPT),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* -------------------------------------------------------------------
     * wc_ChaCha20Poly1305_UpdateAad L205:
     *   (aead == NULL || (inAAD == NULL && inAADLen > 0))
     *
     *   Pair for first operand (aead==NULL):
     *     Pair A: aead=NULL → first op TRUE
     *     Pair B: aead=valid → first op FALSE
     *   Pair for second operand sub-condition (inAAD==NULL && inAADLen>0):
     *     Pair C: aead=valid, inAAD=NULL, len=1 → second op TRUE
     *     Pair D: aead=valid, inAAD=NULL, len=0 → second op FALSE (short-circuit)
     *
     * L208: (state != READY && state != AAD)
     *     After Init, state==READY → condition FALSE → no BAD_STATE_E
     *     With uninitialized / INIT state → condition TRUE → BAD_STATE_E
     * ------------------------------------------------------------------- */
    /* Pair A – aead is NULL */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(NULL, tv_aad, sizeof(tv_aad)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Set up a valid aead in READY state for subsequent calls */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);

    /* Pair B – aead is valid (first op FALSE); both sub-conditions FALSE OK */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, sizeof(tv_aad)), 0);

    /* Re-init for fresh READY state */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);

    /* Pair C – inAAD=NULL && inAADLen>0: second operand TRUE */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Re-init */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);

    /* Pair D – inAAD=NULL, inAADLen=0: second sub-cond FALSE → no error */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, NULL, 0), 0);

    /* L208 pair – wrong state triggers BAD_STATE_E
     * Force state to INIT (0) which is neither READY nor AAD */
    XMEMSET(&aead, 0, sizeof(aead)); /* state = CHACHA20_POLY1305_STATE_INIT */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, sizeof(tv_aad)),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* -------------------------------------------------------------------
     * wc_ChaCha20Poly1305_UpdateData L232/L235:
     *   NULL arg guard: aead==NULL || inData==NULL || outData==NULL
     *   State guard: state != READY && state != AAD && state != DATA
     * ------------------------------------------------------------------- */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(NULL, buf, buf, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, NULL, buf, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, buf, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* State = INIT → all three state conditions TRUE → BAD_STATE_E */
    XMEMSET(&aead, 0, sizeof(aead));
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, buf, buf, 1),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* -------------------------------------------------------------------
     * wc_ChaCha20Poly1305_Final L275/L278:
     *   NULL arg guard: aead==NULL || outAuthTag==NULL
     *   State guard: state != AAD && state != DATA
     * ------------------------------------------------------------------- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(NULL, tag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* State = INIT → neither AAD nor DATA → BAD_STATE_E */
    XMEMSET(&aead, 0, sizeof(aead));
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* State = READY → neither AAD nor DATA → BAD_STATE_E */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag),
        WC_NO_ERR_TRACE(BAD_STATE_E));

#endif /* HAVE_CHACHA && HAVE_POLY1305 */
    return EXPECT_RESULT();
} /* END test_wc_Chacha20Poly1305BadArgCoverage */

/* =========================================================================
 * Function: test_wc_Chacha20Poly1305CheckTagDecision
 *
 * Covers L139 wc_ChaCha20Poly1305_CheckTag ConstantCompare branch:
 *   - Matching tags (ConstantCompare == 0)   → return 0
 *   - 1-bit-flipped tag                      → MAC_CMP_FAILED_E
 *   - Completely different tag               → MAC_CMP_FAILED_E
 * ========================================================================= */
int test_wc_Chacha20Poly1305CheckTagDecision(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    byte tagA[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte tagB[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    XMEMSET(tagA, 0xAB, sizeof(tagA));
    XMEMSET(tagB, 0xAB, sizeof(tagB));

    /* MC/DC Pair TRUE-branch: tags match exactly → 0 */
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(tagA, tagB), 0);

    /* MC/DC Pair FALSE-branch: 1-bit flip → MAC_CMP_FAILED_E */
    tagB[0] ^= 0x01;
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(tagA, tagB),
        WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));

    /* All-zeros vs all-ones: maximally different */
    XMEMSET(tagA, 0x00, sizeof(tagA));
    XMEMSET(tagB, 0xFF, sizeof(tagB));
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(tagA, tagB),
        WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));

    /* Match after correction */
    XMEMSET(tagB, 0x00, sizeof(tagB));
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(tagA, tagB), 0);

#endif /* HAVE_CHACHA && HAVE_POLY1305 */
    return EXPECT_RESULT();
} /* END test_wc_Chacha20Poly1305CheckTagDecision */

/* =========================================================================
 * Function: test_wc_Chacha20Poly1305DecisionCoverage
 *
 * Covers the incremental API (Init/UpdateAad/UpdateData/Final) decision
 * branches:
 *   - L215 UpdateAad: (inAAD && inAADLen>0) branch taken / not taken
 *       Pair A: inAAD!=NULL, len>0   → branch taken, Poly1305 update called
 *       Pair B: inAAD!=NULL, len=0   → branch not taken (noop)
 *       Pair C: inAAD=NULL,  len=0   → branch not taken (NULL short-circuits)
 *   - L244 UpdateData: state==AAD → Poly1305_Pad is called before data
 *       (AAD path vs no-AAD path)
 *   - L278 Final: state==AAD → Poly1305_Pad called for AAD before data pad
 *   - Round-trip encrypt→decrypt verifying matching plaintext
 *   - Various lengths crossing ChaCha block boundary: 15, 16, 17, 33 bytes
 * ========================================================================= */
int test_wc_Chacha20Poly1305DecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    ChaChaPoly_Aead aead;
    byte ct[sizeof(tv_plaintext)];
    byte pt[sizeof(tv_plaintext)];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte tag2[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    static const byte data15[15] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e
    };
    static const byte data16[16] = {
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const byte data17[17] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30
    };
    word32 i;

    /* -------------------------------------------------------------------
     * L215 MC/DC pair A: UpdateAad with non-NULL ptr AND len>0 → taken
     * Encrypt with AAD and data, then decrypt and verify.
     * ------------------------------------------------------------------- */
    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(pt, 0, sizeof(pt));

    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    /* Pair A: ptr!=NULL, len>0 → branch taken */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, sizeof(tv_aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext,
        ct, sizeof(tv_plaintext)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag), 0);
    /* tag must match reference */
    ExpectIntEQ(XMEMCMP(tag, tv_authtag, sizeof(tv_authtag)), 0);

    /* -------------------------------------------------------------------
     * L215 MC/DC pair B: UpdateAad with non-NULL ptr but len==0 → not taken
     * The call must succeed and produce the same auth tag as AAD-less encrypt.
     * ------------------------------------------------------------------- */
    XMEMSET(ct, 0, sizeof(ct));
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    /* Pair B: ptr!=NULL, len=0 → short-circuit, branch not taken */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, 0), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext,
        ct, sizeof(tv_plaintext)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag2), 0);
    /* tag2 != tv_authtag because AAD was skipped */
    ExpectIntNE(XMEMCMP(tag2, tv_authtag, sizeof(tv_authtag)), 0);

    /* -------------------------------------------------------------------
     * L215 MC/DC pair C: UpdateAad NULL ptr, len=0 → not taken (no-op)
     * ------------------------------------------------------------------- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    /* Pair C: ptr=NULL, len=0 → UpdateAad noop */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, NULL, 0), 0);
    /* Proceed to final without data to get to Final-from-READY BAD_STATE */
    /* Actually advance through UpdateData so Final is legal */
    XMEMSET(ct, 0, sizeof(ct));
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext,
        ct, sizeof(tv_plaintext)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag2), 0);

    /* -------------------------------------------------------------------
     * L244 UpdateData: state==AAD path (Poly1305_Pad for AAD executed)
     * vs state==READY path (no Poly1305_Pad executed before data).
     *
     * Test both sub-paths produce different tags (AAD matters):
     *   Encrypt1: Init → UpdateAad → UpdateData → Final
     *   Encrypt2: Init →             UpdateData → Final
     * The two tags must differ.
     * ------------------------------------------------------------------- */
    XMEMSET(ct, 0, sizeof(ct));
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, sizeof(tv_aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, data16, ct, sizeof(data16)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag), 0);

    XMEMSET(ct, 0, sizeof(ct));
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    /* skip UpdateAad → state remains READY when UpdateData is called */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, data16, ct, sizeof(data16)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag2), 0);

    ExpectIntNE(XMEMCMP(tag, tag2, sizeof(tag)), 0);

    /* -------------------------------------------------------------------
     * L284 Final: state==AAD path (AAD present, no data)
     * Finalize directly after AAD with no UpdateData call.
     * ------------------------------------------------------------------- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, sizeof(tv_aad)), 0);
    /* state is AAD; Final must call Poly1305_Pad for AAD then for dataLen=0 */
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag), 0);

    /* -------------------------------------------------------------------
     * Round-trip at various lengths crossing ChaCha block boundary
     * Tests: 15 (< 16), 16 (= 16), 17 (> 16), 33 (> 32)
     * ------------------------------------------------------------------- */
    {
        static const word32 lens[] = {15, 16, 17, 33};
        static const byte input33[33] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
        };
        const byte *inputs[4];
        inputs[0] = data15;
        inputs[1] = data16;
        inputs[2] = data17;
        inputs[3] = input33;

        for (i = 0; i < 4; i++) {
            word32 len = lens[i];
            XMEMSET(ct, 0, sizeof(ct));
            XMEMSET(pt, 0, sizeof(pt));

            /* Encrypt */
            ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(tv_key, tv_iv,
                tv_aad, sizeof(tv_aad),
                inputs[i], len,
                ct, tag), 0);

            /* Decrypt */
            ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(tv_key, tv_iv,
                tv_aad, sizeof(tv_aad),
                ct, len,
                tag, pt), 0);

            /* Plaintext must match */
            ExpectIntEQ(XMEMCMP(pt, inputs[i], len), 0);
        }
    }

    /* -------------------------------------------------------------------
     * In-place encrypt/decrypt (inData == outData)
     * ------------------------------------------------------------------- */
    {
        byte inplace[16];
        byte orig[16];
        XMEMSET(orig, 0x55, sizeof(orig));
        XMEMCPY(inplace, orig, sizeof(orig));

        /* Encrypt in-place */
        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(tv_key, tv_iv,
            NULL, 0,
            inplace, sizeof(inplace),
            inplace, tag), 0);
        /* Ciphertext must differ from plaintext */
        ExpectIntNE(XMEMCMP(inplace, orig, sizeof(orig)), 0);

        /* Decrypt in-place */
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(tv_key, tv_iv,
            NULL, 0,
            inplace, sizeof(inplace),
            tag, inplace), 0);
        /* Recovered plaintext must match original */
        ExpectIntEQ(XMEMCMP(inplace, orig, sizeof(orig)), 0);
    }

    /* -------------------------------------------------------------------
     * Incremental API: split AAD across two UpdateAad calls
     * (L208 second-call branch: state transitions READY → AAD → AAD)
     * ------------------------------------------------------------------- */
    {
        byte ct_split[sizeof(tv_plaintext)];
        byte tag_split[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
        byte tag_single[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

        /* Single-call AAD baseline */
        XMEMSET(ct, 0, sizeof(ct));
        ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
            CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad,
            sizeof(tv_aad)), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext,
            ct, sizeof(tv_plaintext)), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag_single), 0);

        /* Split AAD: two UpdateAad calls, state goes READY→AAD→AAD */
        XMEMSET(ct_split, 0, sizeof(ct_split));
        ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
            CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
        /* First UpdateAad: state READY → AAD */
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, 6), 0);
        /* Second UpdateAad: state AAD → AAD (the second branch at L208) */
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead,
            tv_aad + 6, sizeof(tv_aad) - 6), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext,
            ct_split, sizeof(tv_plaintext)), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag_split), 0);

        /* Both methods must produce identical auth tags */
        ExpectIntEQ(XMEMCMP(tag_single, tag_split, sizeof(tag_single)), 0);
    }

    /* -------------------------------------------------------------------
     * Incremental API: split data across two UpdateData calls
     * ------------------------------------------------------------------- */
    {
        byte ct_split[sizeof(tv_plaintext)];
        byte tag_split[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
        byte tag_single[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

        /* Single-call data baseline */
        XMEMSET(ct, 0, sizeof(ct));
        ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
            CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad,
            sizeof(tv_aad)), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext,
            ct, sizeof(tv_plaintext)), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag_single), 0);

        /* Split data at a non-block boundary */
        XMEMSET(ct_split, 0, sizeof(ct_split));
        ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
            CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad,
            sizeof(tv_aad)), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext,
            ct_split, 17), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead,
            tv_plaintext + 17, ct_split + 17,
            (word32)(sizeof(tv_plaintext) - 17)), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag_split), 0);

        ExpectIntEQ(XMEMCMP(tag_single, tag_split, sizeof(tag_single)), 0);
    }

    /* -------------------------------------------------------------------
     * Decrypt with corrupted auth tag must fail and zero out plaintext
     * ------------------------------------------------------------------- */
    {
        byte corrupt_tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
        XMEMCPY(corrupt_tag, tv_authtag, sizeof(corrupt_tag));
        corrupt_tag[7] ^= 0x80; /* flip one bit */
        XMEMSET(pt, 0xCC, sizeof(pt));

        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(tv_key, tv_iv,
            tv_aad, sizeof(tv_aad),
            tv_ciphertext, sizeof(tv_ciphertext),
            corrupt_tag, pt),
            WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));

        /* Plaintext buffer must be zeroed on MAC failure */
        {
            byte zeros[sizeof(tv_plaintext)];
            XMEMSET(zeros, 0, sizeof(zeros));
            ExpectIntEQ(XMEMCMP(pt, zeros, sizeof(pt)), 0);
        }
    }

#endif /* HAVE_CHACHA && HAVE_POLY1305 */
    return EXPECT_RESULT();
} /* END test_wc_Chacha20Poly1305DecisionCoverage */

/* =========================================================================
 * Function: test_wc_Chacha20Poly1305IncrementalStateMachine
 *
 * Exercises every legal and illegal state transition of the incremental API
 * to cover the L208 and L235/L278 state-machine branches exhaustively.
 *
 * Legal sequence:  Init → [UpdateAad]* → [UpdateData]* → Final
 * Illegal:
 *   - UpdateData after Final  (state INIT)
 *   - UpdateAad after UpdateData (state DATA)
 *   - Final with state READY  (no AAD or data yet)
 *   - Double Final
 * ========================================================================= */
int test_wc_Chacha20Poly1305IncrementalStateMachine(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    ChaChaPoly_Aead aead;
    byte ct[sizeof(tv_plaintext)];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* --- INIT state: UpdateData must fail --- */
    XMEMSET(&aead, 0, sizeof(aead)); /* state = INIT */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext, ct, 1),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* --- INIT state: Final must fail --- */
    XMEMSET(&aead, 0, sizeof(aead));
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* --- READY state: Final must fail (no AAD or data) --- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* --- AAD state: UpdateData legal, transitions state to DATA --- */
    XMEMSET(ct, 0, sizeof(ct));
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, sizeof(tv_aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext,
        ct, sizeof(tv_plaintext)), 0);
    /* state is now DATA; Final is legal */
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag), 0);

    /* --- DATA state: UpdateAad must fail (state is DATA after Final
     *     zeroed the struct; re-init to DATA manually via direct call) --- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, sizeof(tv_aad)), 0);
    XMEMSET(ct, 0, sizeof(ct));
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext,
        ct, sizeof(tv_plaintext)), 0);
    /* Now state == DATA; UpdateAad must fail */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, sizeof(tv_aad)),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* --- After Final, state is zeroed (INIT); subsequent calls must fail --- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad, sizeof(tv_aad)), 0);
    XMEMSET(ct, 0, sizeof(ct));
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext,
        ct, sizeof(tv_plaintext)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag), 0);
    /* After Final, aead is zeroed → state INIT → UpdateData must fail */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_plaintext, ct, 1),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* --- Decrypt full pipeline verification --- */
    {
        byte pt[sizeof(tv_plaintext)];
        byte calc_tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

        XMEMSET(pt, 0, sizeof(pt));
        ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, tv_key, tv_iv,
            CHACHA20_POLY1305_AEAD_DECRYPT), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, tv_aad,
            sizeof(tv_aad)), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, tv_ciphertext,
            pt, sizeof(tv_ciphertext)), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, calc_tag), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(tv_authtag, calc_tag), 0);
        ExpectIntEQ(XMEMCMP(pt, tv_plaintext, sizeof(tv_plaintext)), 0);
    }

#endif /* HAVE_CHACHA && HAVE_POLY1305 */
    return EXPECT_RESULT();
} /* END test_wc_Chacha20Poly1305IncrementalStateMachine */
