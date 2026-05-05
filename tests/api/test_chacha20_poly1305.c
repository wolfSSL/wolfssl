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

/*
 * Testing wc_ChaCha20Poly1305_Encrypt() and wc_ChaCha20Poly1305_Decrypt()
 */
int test_wc_ChaCha20Poly1305_aead(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    const byte  key[] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    const byte  plaintext[] = {
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
    const byte  iv[] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    const byte  aad[] = { /* additional data */
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    const byte  cipher[] = { /* expected output from operation */
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
    const byte  authTag[] = { /* expected output from operation */
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    byte        generatedCiphertext[272];
    byte        generatedPlaintext[272];
    byte        generatedAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* Initialize stack variables. */
    XMEMSET(generatedCiphertext, 0, 272);
    XMEMSET(generatedPlaintext, 0, 272);

    /* Test Encrypt */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext), generatedCiphertext, generatedAuthTag),
        0);
    ExpectIntEQ(XMEMCMP(generatedCiphertext, cipher,
        sizeof(cipher)/sizeof(byte)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(NULL, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, NULL, aad, sizeof(aad),
        plaintext, sizeof(plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad), NULL,
        sizeof(plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        NULL, sizeof(plaintext), generatedCiphertext, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext), NULL, generatedAuthTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext), generatedCiphertext, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad), cipher,
        sizeof(cipher), authTag, generatedPlaintext), 0);
    ExpectIntEQ(XMEMCMP(generatedPlaintext, plaintext,
        sizeof(plaintext)/sizeof(byte)), 0);

    /* Test bad args. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(NULL, iv, aad, sizeof(aad), cipher,
        sizeof(cipher), authTag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, NULL, aad, sizeof(aad),
        cipher, sizeof(cipher), authTag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad), NULL,
        sizeof(cipher), authTag, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad), cipher,
        sizeof(cipher), NULL, generatedPlaintext),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad), cipher,
        sizeof(cipher), authTag, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad), NULL,
        sizeof(cipher), authTag, generatedPlaintext),
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

/*
 * Testing wc_ChaCha20Poly1305_Init(), wc_ChaCha20Poly1305_UpdateAad(),
 * wc_ChaCha20Poly1305_UpdateData(), and wc_ChaCha20Poly1305_Final()
 * streaming API using the RFC 8439 Section 2.8.2 test vector.
 */
int test_wc_ChaCha20Poly1305_Stream(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    /* RFC 8439 Section 2.8.2 test vector */
    static const byte key[] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const byte iv[] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    static const byte aad[] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    static const byte plaintext[] = {
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
    static const byte expCipher[] = {
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
    static const byte expAuthTag[] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    ChaChaPoly_Aead aead;
    byte outCipher[sizeof(plaintext)];
    byte outPlain[sizeof(plaintext)];
    byte outTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* --- Streaming encrypt: AAD in two chunks, plaintext in three chunks --- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, 6), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad + 6,
        (word32)(sizeof(aad) - 6)), 0);
    XMEMSET(outCipher, 0, sizeof(outCipher));
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plaintext,
        outCipher, 38), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plaintext + 38,
        outCipher + 38, 38), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plaintext + 76,
        outCipher + 76, (word32)(sizeof(plaintext) - 76)), 0);
    XMEMSET(outTag, 0, sizeof(outTag));
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, outTag), 0);
    ExpectBufEQ(outCipher, expCipher, sizeof(expCipher));
    ExpectBufEQ(outTag, expAuthTag, sizeof(expAuthTag));

    /* --- Streaming decrypt: single AAD chunk, ciphertext in three chunks --- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
        CHACHA20_POLY1305_AEAD_DECRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad,
        (word32)sizeof(aad)), 0);
    XMEMSET(outPlain, 0, sizeof(outPlain));
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, expCipher,
        outPlain, 38), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, expCipher + 38,
        outPlain + 38, 38), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, expCipher + 76,
        outPlain + 76, (word32)(sizeof(expCipher) - 76)), 0);
    XMEMSET(outTag, 0, sizeof(outTag));
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, outTag), 0);
    ExpectBufEQ(outPlain, plaintext, sizeof(plaintext));
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(outTag, expAuthTag), 0);

    /* --- Bad args --- */
    /* wc_ChaCha20Poly1305_Init: NULL aead */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(NULL, key, iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* wc_ChaCha20Poly1305_Init: NULL key */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, NULL, iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* wc_ChaCha20Poly1305_Init: NULL iv */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, NULL,
        CHACHA20_POLY1305_AEAD_ENCRYPT),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* wc_ChaCha20Poly1305_UpdateAad: NULL aead */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(NULL, aad, (word32)sizeof(aad)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* wc_ChaCha20Poly1305_UpdateData: NULL aead */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(NULL, plaintext, outCipher,
        (word32)sizeof(plaintext)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* wc_ChaCha20Poly1305_Final: NULL aead */
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(NULL, outTag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* wc_ChaCha20Poly1305_Final: wrong state (INIT, not AAD/DATA) */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, outTag),
        WC_NO_ERR_TRACE(BAD_STATE_E));
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_Stream */

/*
 * ChaCha20-Poly1305 AEAD edge cases:
 *   - invalid auth tag rejection (one-shot API)
 *   - empty plaintext with non-empty AAD (streaming API)
 */
int test_wc_ChaCha20Poly1305_AeadEdgeCases(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    /* RFC 8439 Section 2.8.2 key/iv/aad */
    static const byte key[] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const byte iv[] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    static const byte aad[] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    static const byte plaintext[] = {
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
    ChaChaPoly_Aead aead;
    byte cipherOut[sizeof(plaintext)];
    byte plainOut[sizeof(plaintext)];
    byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte authTagDecrypt[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* --- Invalid tag rejection (one-shot API) ---
     * Encrypt with correct key/iv/aad/pt, then flip a tag byte and
     * verify that Decrypt returns MAC_CMP_FAILED_E. */
    XMEMSET(cipherOut, 0, sizeof(cipherOut));
    XMEMSET(authTag,   0, sizeof(authTag));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext), cipherOut, authTag), 0);
    authTag[0] ^= 0xff;
    XMEMSET(plainOut, 0, sizeof(plainOut));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad),
        cipherOut, sizeof(cipherOut), authTag, plainOut),
        WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));

    /* --- Empty plaintext with non-empty AAD (streaming API) ---
     * Init + UpdateAad + Final, no UpdateData call.
     * Correct computed tag must verify; tampered tag must fail. */
    XMEMSET(authTag,       0, sizeof(authTag));
    XMEMSET(authTagDecrypt, 0, sizeof(authTagDecrypt));

    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, authTag), 0);

    /* Decrypt with same AAD and no data; verify tag matches */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
        CHACHA20_POLY1305_AEAD_DECRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, authTagDecrypt), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(authTagDecrypt, authTag), 0);

    /* Tamper and verify CheckTag rejects it */
    authTagDecrypt[0] ^= 0xff;
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(authTagDecrypt, authTag),
        WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_AeadEdgeCases */

/*******************************************************************************
 * ChaCha20-Poly1305 mid-stream state corruption
 ******************************************************************************/

/*
 * Verify that the ChaCha20-Poly1305 streaming state machine rejects operations
 * called in the wrong order, and handles post-Final reuse gracefully.
 *
 * State transitions:  INIT(0) -> READY(1) -> AAD(2) -> DATA(3)
 *   UpdateAad: READY or AAD only
 *   UpdateData: READY, AAD, or DATA
 *   Final:      AAD or DATA only
 * After Final, ForceZero resets the struct to all-zeros (state == INIT).
 */
int test_wc_ChaCha20Poly1305_MidStreamState(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    static const byte key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
        0x80,0x81,0x82,0x83, 0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b, 0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93, 0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b, 0x9c,0x9d,0x9e,0x9f
    };
    static const byte iv[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47
    };
    static const byte aad[8]   = { 0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3 };
    static const byte plain[8] = { 0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07 };
    ChaChaPoly_Aead aead;
    byte ct[8];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* ------------------------------------------------------------------
     * Test 1: UpdateAad after UpdateData (DATA state) -> BAD_STATE_E
     * Once UpdateData has been called the state advances to DATA and any
     * further UpdateAad calls must be rejected.
     * ------------------------------------------------------------------ */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plain, ct,
        sizeof(plain)), 0);
    /* State is now DATA - UpdateAad must fail. */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    /* Clean up the aead object so the next test starts fresh. */
    XMEMSET(&aead, 0, sizeof(aead));

    /* ------------------------------------------------------------------
     * Test 2: UpdateData in INIT state (no Init called) -> BAD_STATE_E
     * state == INIT(0): UpdateData requires READY(1), AAD(2), or DATA(3).
     * ------------------------------------------------------------------ */
    /* aead was zeroed above so state == INIT. */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plain, ct, sizeof(plain)),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* ------------------------------------------------------------------
     * Test 3: Reuse after Final - state reset to INIT by ForceZero
     * wc_ChaCha20Poly1305_Final calls ForceZero on the whole struct, which
     * sets state back to INIT(0).  Any subsequent streaming call must fail.
     * ------------------------------------------------------------------ */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)), 0);
    /* First Final succeeds (state == AAD). */
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag), 0);
    /* State is now INIT (all zeros after ForceZero). */
    /* Second Final must fail. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    /* UpdateAad after Final must also fail. */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    /* UpdateData after Final must also fail. */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plain, ct, sizeof(plain)),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* ------------------------------------------------------------------
     * Test 4: Direct state field corruption to an invalid value
     * Forcing state to a value outside the defined enum range makes all
     * state-checking calls return BAD_STATE_E.
     * ------------------------------------------------------------------ */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    /* Corrupt state: 99 is not a valid CHACHA20_POLY1305_STATE_* value. */
    aead.state = 99;
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plain, ct, sizeof(plain)),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag),
        WC_NO_ERR_TRACE(BAD_STATE_E));
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_MidStreamState */

/*******************************************************************************
 * ChaCha20-Poly1305 re-initialization after Final
 ******************************************************************************/

/*
 * Verify that a ChaCha20-Poly1305 AEAD context can be re-initialized and
 * reused after wc_ChaCha20Poly1305_Final has been called.
 *
 * wc_ChaCha20Poly1305_Final calls ForceZero on the whole ChaChaPoly_Aead
 * struct, so a fresh wc_ChaCha20Poly1305_Init is needed before the next
 * session.  These tests confirm:
 *
 *  1. Re-init with the same key and IV produces identical ciphertext and tag.
 *  2. Re-init with a different IV produces different ciphertext and tag.
 *  3. Re-init after an *abandoned* session (Init but no Final) also works.
 */
int test_wc_ChaCha20Poly1305_ReinitAfterFinal(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    static const byte key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
        0x80,0x81,0x82,0x83, 0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b, 0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93, 0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b, 0x9c,0x9d,0x9e,0x9f
    };
    static const byte iv1[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47
    };
    /* Distinct IV - same length, one byte different. */
    static const byte iv2[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x48
    };
    static const byte aad[]   = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3,
        0xc4,0xc5,0xc6,0xc7
    };
    static const byte plain[] = {
        0x4c,0x61,0x64,0x69, 0x65,0x73,0x20,0x61,
        0x6e,0x64,0x20,0x47, 0x65,0x6e,0x74,0x6c
    };
    ChaChaPoly_Aead aead;
    byte ct1[sizeof(plain)];
    byte ct2[sizeof(plain)];
    byte ct3[sizeof(plain)];
    byte tag1[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte tag2[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte tag3[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* ---- Session 1: establish baseline ciphertext and tag ---- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv1,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plain, ct1,
        sizeof(plain)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag1), 0);

    /* ---- Session 2: re-init with the same key and IV ---- */
    /* aead was ForceZero'd by Final; Init must succeed. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv1,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plain, ct2,
        sizeof(plain)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag2), 0);
    /* Same key + IV must produce identical output. */
    ExpectBufEQ(ct2,  ct1,  sizeof(ct1));
    ExpectBufEQ(tag2, tag1, sizeof(tag1));

    /* ---- Session 3: re-init with a different IV ---- */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv2,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plain, ct3,
        sizeof(plain)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag3), 0);
    /* Different IV must produce different ciphertext and tag. */
    ExpectIntNE(XMEMCMP(ct3,  ct1,  sizeof(ct1)),  0);
    ExpectIntNE(XMEMCMP(tag3, tag1, sizeof(tag1)), 0);

    /* ---- Session 4: re-init after an abandoned session ----
     * Start a session (Init + UpdateAad) but never call Final.
     * Then re-init and complete normally - must match session 1. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv2,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)), 0);
    /* Abandon this session - manually reset before re-init. */
    XMEMSET(&aead, 0, sizeof(aead));
    /* Now re-init with iv1 and verify we get session-1 output again. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv1,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, plain, ct2,
        sizeof(plain)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tag2), 0);
    ExpectBufEQ(ct2,  ct1,  sizeof(ct1));
    ExpectBufEQ(tag2, tag1, sizeof(tag1));
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_ReinitAfterFinal */

/*
 * Verify that wc_ChaCha20Poly1305_Encrypt and wc_ChaCha20Poly1305_Decrypt work
 * correctly when the plaintext/ciphertext pointer is the same buffer (in-place
 * operation).  The cipher uses a ChaCha20 keystream XOR, so in == out is safe.
 * The Poly1305 tag is always a separate output buffer.
 *
 * RFC 8439 2.8.2 key, IV, and AAD are used with a 64-byte counter-pattern
 * plaintext (self-consistency: reference ciphertext computed at test time).
 */
int test_wc_ChaCha20Poly1305_InPlace(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    static const byte key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
        0x80,0x81,0x82,0x83, 0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b, 0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93, 0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b, 0x9c,0x9d,0x9e,0x9f
    };
    static const byte iv[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47
    };
    static const byte aad[12] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3, 0xc4,0xc5,0xc6,0xc7
    };
    /* 67-byte counter pattern: spans one full ChaCha20 block (64 B) plus
     * a 3-byte partial tail, exercising both full-block and leftover paths. */
    static const byte plain[67] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23, 0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b, 0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33, 0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b, 0x3c,0x3d,0x3e,0x3f,
        0x40,0x41,0x42
    };
    byte ref_ct[sizeof(plain)], ref_tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte buf[sizeof(plain)],    tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* Reference ciphertext with separate in/out buffers */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv,
        aad, sizeof(aad), plain, sizeof(plain), ref_ct, ref_tag), 0);

    /* Encrypt in-place (outCiphertext == inPlaintext) */
    XMEMCPY(buf, plain, sizeof(buf));
    XMEMSET(tag, 0, sizeof(tag));
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv,
        aad, sizeof(aad), buf, sizeof(buf), buf, tag), 0);
    ExpectBufEQ(buf, ref_ct,  sizeof(buf));
    ExpectBufEQ(tag, ref_tag, sizeof(tag));

    /* Decrypt in-place (outPlaintext == inCiphertext) */
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv,
        aad, sizeof(aad), buf, sizeof(buf), tag, buf), 0);
    ExpectBufEQ(buf, plain, sizeof(buf));
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_InPlace */

/*
 * Verify that wc_ChaCha20Poly1305_Encrypt and wc_ChaCha20Poly1305_Decrypt
 * produce correct results when plaintext, ciphertext, and AAD buffers are
 * byte-offset (unaligned).  Tests offsets 1, 2, and 3.
 */
int test_wc_ChaCha20Poly1305_UnalignedBuffers(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    /* Same key / IV / AAD as InPlace test */
    static const byte key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
        0x80,0x81,0x82,0x83, 0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b, 0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93, 0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b, 0x9c,0x9d,0x9e,0x9f
    };
    static const byte iv[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47
    };
    static const byte aad[12] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3, 0xc4,0xc5,0xc6,0xc7
    };
    /* 67-byte counter pattern - same as InPlace test */
    static const byte plain[67] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23, 0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b, 0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33, 0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b, 0x3c,0x3d,0x3e,0x3f,
        0x40,0x41,0x42
    };
    byte ref_ct[sizeof(plain)], ref_tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte in_buf[sizeof(plain) + 3], out_buf[sizeof(plain) + 3];
    byte aad_buf[sizeof(aad) + 3];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    int off;

    /* Reference ciphertext/tag with naturally-aligned buffers */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv,
        aad, sizeof(aad), plain, sizeof(plain), ref_ct, ref_tag), 0);

    /* Encrypt with byte offsets 1, 2, 3 on plaintext, ciphertext, and AAD */
    for (off = 1; off <= 3 && EXPECT_SUCCESS(); off++) {
        XMEMCPY(in_buf  + off, plain, sizeof(plain));
        XMEMCPY(aad_buf + off, aad,   sizeof(aad));
        XMEMSET(out_buf, 0, sizeof(out_buf));
        XMEMSET(tag,     0, sizeof(tag));
        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv,
            aad_buf + off, sizeof(aad), in_buf + off, sizeof(plain),
            out_buf + off, tag), 0);
        ExpectBufEQ(out_buf + off, ref_ct,  sizeof(plain));
        ExpectBufEQ(tag,           ref_tag, sizeof(tag));
    }

    /* Decrypt with byte offsets 1, 2, 3 */
    for (off = 1; off <= 3 && EXPECT_SUCCESS(); off++) {
        XMEMCPY(in_buf  + off, ref_ct, sizeof(plain));
        XMEMCPY(aad_buf + off, aad,    sizeof(aad));
        XMEMSET(out_buf, 0, sizeof(out_buf));
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv,
            aad_buf + off, sizeof(aad), in_buf + off, sizeof(plain),
            ref_tag, out_buf + off), 0);
        ExpectBufEQ(out_buf + off, plain, sizeof(plain));
    }
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_UnalignedBuffers */

/*
 * Cross-cipher test: ChaCha20-Poly1305 encrypts plaintext using ChaCha20 with
 * the block counter starting at 1.  Counter 0 is reserved for generating the
 * 32-byte Poly1305 one-time key; plaintext encryption begins at counter 1.
 *
 * This test verifies that the ciphertext produced by
 * wc_ChaCha20Poly1305_Encrypt equals the output of wc_Chacha_Process when
 * the counter is initialised to 1 via wc_Chacha_SetIV(ctx, iv, 1).
 */
int test_wc_ChaCha20Poly1305_CrossCipher(void)
{
    EXPECT_DECLS;
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    ChaCha ctx;
    /* Same key / IV / plain as the InPlace and UnalignedBuffers tests */
    static const byte key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
        0x80,0x81,0x82,0x83, 0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b, 0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93, 0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b, 0x9c,0x9d,0x9e,0x9f
    };
    static const byte iv[CHACHA20_POLY1305_AEAD_IV_SIZE] = {
        0x07,0x00,0x00,0x00, 0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47
    };
    static const byte aad[12] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3, 0xc4,0xc5,0xc6,0xc7
    };
    static const byte plain[67] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23, 0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b, 0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33, 0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b, 0x3c,0x3d,0x3e,0x3f,
        0x40,0x41,0x42
    };
    byte aead_ct[sizeof(plain)], aead_tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte chacha_ct[sizeof(plain)];

    /* ChaCha20-Poly1305 ciphertext */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv,
        aad, sizeof(aad), plain, sizeof(plain), aead_ct, aead_tag), 0);

    /* ChaCha20 ciphertext with counter=1 (counter 0 is the Poly1305 key block) */
    ExpectIntEQ(wc_Chacha_SetKey(&ctx, key, sizeof(key)), 0);
    ExpectIntEQ(wc_Chacha_SetIV(&ctx, iv, 1), 0);
    ExpectIntEQ(wc_Chacha_Process(&ctx, chacha_ct, plain, sizeof(plain)), 0);

    /* ChaCha20-Poly1305 ciphertext must equal ChaCha20(counter=1) ciphertext */
    ExpectBufEQ(aead_ct, chacha_ct, sizeof(plain));
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_CrossCipher */
