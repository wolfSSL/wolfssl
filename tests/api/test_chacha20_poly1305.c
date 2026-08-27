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

int test_wc_XChaCha20Poly1305_BadAuthTag(void)
{
    EXPECT_DECLS;
#if defined(HAVE_POLY1305) && defined(HAVE_XCHACHA)
    const byte key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    const byte nonce[24] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57
    };
    const byte plaintext[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x73
    };
    const byte aad[] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3
    };
    byte ct[sizeof(plaintext) + 16];
    byte pt[sizeof(plaintext)];
    byte ct_bad[sizeof(ct)];
    byte aad_bad[sizeof(aad)];

    XMEMSET(ct, 0, sizeof(ct));

    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(ct, sizeof(ct),
        plaintext, sizeof(plaintext), aad, sizeof(aad),
        nonce, sizeof(nonce), key, sizeof(key)), 0);

    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(pt, sizeof(pt), ct, sizeof(ct),
        aad, sizeof(aad), nonce, sizeof(nonce), key, sizeof(key)), 0);

    XMEMCPY(ct_bad, ct, sizeof(ct));
    ct_bad[sizeof(ct) - 1] ^= 0x01;
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(pt, sizeof(pt), ct_bad,
        sizeof(ct_bad), aad, sizeof(aad), nonce, sizeof(nonce),
        key, sizeof(key)),
        WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));

    XMEMCPY(ct_bad, ct, sizeof(ct));
    ct_bad[0] ^= 0x01;
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(pt, sizeof(pt), ct_bad,
        sizeof(ct_bad), aad, sizeof(aad), nonce, sizeof(nonce),
        key, sizeof(key)),
        WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));

    XMEMCPY(aad_bad, aad, sizeof(aad));
    aad_bad[0] ^= 0x01;
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(pt, sizeof(pt), ct, sizeof(ct),
        aad_bad, sizeof(aad_bad), nonce, sizeof(nonce),
        key, sizeof(key)),
        WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
#endif
    return EXPECT_RESULT();
}

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
    byte aad[32];
    word32 aadLen = 0;
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

        /* Random AAD (0..sizeof(aad)) so the AAD fold is exercised alongside
         * every randomly-chosen message size, including the sz <= 64 small
         * kernel band. */
        ExpectIntEQ(wc_RNG_GenerateBlock(&rng, (byte*)&aadLen,
            sizeof(aadLen)), 0);
        aadLen = aadLen % (word32)(sizeof(aad) + 1);
        if (aadLen > 0)
            ExpectIntEQ(wc_RNG_GenerateBlock(&rng, aad, aadLen), 0);

        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, nonce, aad, aadLen,
            plain, plainLen, cipher, tag), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, nonce, aad, aadLen,
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

/*******************************************************************************
 * ChaCha20-Poly1305 residual MC/DC decision coverage
 *
 * The rest of the suite above already flips both sides of: every one-shot
 * Encrypt/Decrypt NULL-pointer arg check except the plaintext/ciphertext
 * NULL-with-zero-length independence pair; the streaming Init/UpdateAad/
 * UpdateData/Final state-machine transitions (MidStreamState); the AAD/data
 * padding true/false split; isEncrypt; and the tag-compare success/failure
 * paths (AeadEdgeCases). What remains is closed here:
 *
 *   - wc_ChaCha20Poly1305_Encrypt/Decrypt: the "(len > 0 && ptr == NULL)"
 *     check's false-side independence pair (NULL pointer + zero length must
 *     SUCCEED, not fail) - the true side is already covered elsewhere.
 *   - wc_ChaCha20Poly1305_CheckTag: neither NULL operand is exercised
 *     anywhere else in the suite (only ever called with two valid buffers).
 *   - wc_ChaCha20Poly1305_UpdateAad: NULL inAAD + non-zero inAADLen called
 *     DIRECTLY (the one-shot API only ever forwards a NULL aad with length
 *     0); valid pointer + zero length (the block-guard's false side, state
 *     must stay READY rather than advancing to AAD).
 *   - wc_ChaCha20Poly1305_UpdateData: NULL inData / NULL outData - never
 *     exercised (every existing call uses two valid buffers).
 *   - wc_ChaCha20Poly1305_Final: NULL outAuthTag - never exercised (only the
 *     NULL-aead operand of that same check is tested elsewhere).
 *   - wc_ChaCha20Poly1305_UpdateAad / UpdateData: the CHACHA_POLY_OVERFLOW
 *     true branch is never taken anywhere else (every AAD/data length used
 *     is tiny). The overflow comparison runs before the buffer is ever
 *     dereferenced, so a real (small) buffer pointer paired with an
 *     out-of-range word32 length is safe to pass.
 ******************************************************************************/
int test_wc_ChaCha20Poly1305_DecisionCoverage(void)
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
    static const byte data[4] = { 0x00, 0x01, 0x02, 0x03 };
    ChaChaPoly_Aead aead;
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte dummyOut[1];
    byte emptyBuf[1];
    byte outBuf[4];

    XMEMSET(&aead, 0, sizeof(aead));
    XMEMSET(tag,     0, sizeof(tag));
    XMEMSET(dummyOut, 0, sizeof(dummyOut));
    XMEMSET(emptyBuf, 0, sizeof(emptyBuf));
    XMEMSET(outBuf,   0, sizeof(outBuf));

    /* --- One-shot Encrypt/Decrypt: NULL plaintext/ciphertext + zero length.
     * Independence pair (holding "inPlaintext == NULL" fixed true) for the
     * "inPlaintextLen > 0" operand of "(inPlaintextLen > 0 &&
     * inPlaintext == NULL)": with inPlaintextLen == 0 this specific
     * AND-term evaluates false, so the top-level arg check no longer
     * returns BAD_FUNC_ARG directly from *this* line - control instead
     * reaches the internal wc_ChaCha20Poly1305_UpdateData() call, whose OWN
     * arg check rejects a NULL inData/outData pointer unconditionally
     * regardless of length, so the end-to-end return code is still
     * BAD_FUNC_ARG (via a different source line). The true side (non-zero
     * length + NULL pointer, caught directly by the top-level check) is
     * already covered by test_wc_ChaCha20Poly1305_aead. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        NULL, 0, dummyOut, tag), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad),
        NULL, 0, tag, dummyOut), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- One-shot Encrypt/Decrypt: zero-length plaintext/ciphertext with a
     * valid (non-NULL) pointer must SUCCEED - the one-shot wrapper supports
     * an empty AEAD message when given a real (if unused) buffer; only the
     * streaming API's empty-message case is covered elsewhere
     * (AeadEdgeCases). */
    ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, sizeof(aad),
        emptyBuf, 0, dummyOut, tag), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, sizeof(aad),
        emptyBuf, 0, tag, dummyOut), 0);

    /* --- wc_ChaCha20Poly1305_CheckTag: NULL operand independence pairs. */
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(NULL, tag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(tag, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- wc_ChaCha20Poly1305_UpdateAad: NULL inAAD + non-zero inAADLen,
     * called directly while state == READY. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, NULL, 5),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Arg-check failure must not have advanced the state - still READY. */
    ExpectIntEQ(aead.state, CHACHA20_POLY1305_STATE_READY);

    /* --- wc_ChaCha20Poly1305_UpdateAad: valid pointer + zero length ->
     * success, and the "inAAD && inAADLen > 0" block-guard false branch is
     * taken - state must stay READY (not advance to AAD). */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, 0), 0);
    ExpectIntEQ(aead.state, CHACHA20_POLY1305_STATE_READY);

    /* --- wc_ChaCha20Poly1305_UpdateData: NULL inData / NULL outData. */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, NULL, outBuf,
        sizeof(data)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, data, NULL,
        sizeof(data)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- wc_ChaCha20Poly1305_Final: NULL outAuthTag. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- wc_ChaCha20Poly1305_UpdateAad: CHACHA_POLY_OVERFLOW true branch.
     * Never exercised elsewhere: every existing AAD length is tiny. The
     * overflow check runs before inAAD is dereferenced, so a real (small)
     * buffer paired with an out-of-range length value is safe. */
    ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
        CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, sizeof(aad)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad,
        CHACHA20_POLY1305_MAX), WC_NO_ERR_TRACE(CHACHA_POLY_OVERFLOW));

    /* --- wc_ChaCha20Poly1305_UpdateData: CHACHA_POLY_OVERFLOW true branch,
     * same reasoning as above but for the data-length accumulator. */
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, data, outBuf,
        sizeof(data)), 0);
    ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, data, outBuf,
        CHACHA20_POLY1305_MAX), WC_NO_ERR_TRACE(CHACHA_POLY_OVERFLOW));
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_DecisionCoverage */

/*******************************************************************************
 * XChaCha20-Poly1305 residual MC/DC decision coverage
 *
 *   - wc_XChaCha20Poly1305_Init: NULL aead - never reachable through the
 *     Encrypt/Decrypt one-shot wrappers, which always pass an internal,
 *     valid aead pointer; ad == NULL + ad_len == 0 success - independence
 *     pair (holding ad == NULL fixed) for the ad_len operand of
 *     "(ad == NULL && ad_len > 0)". The true side of that AND, and the
 *     ad-pointer operand's own independence pair, are already exercised via
 *     test_wc_XChaCha20Poly1305_aead's bad-arg Encrypt calls.
 *   - wc_XChaCha20Poly1305_Decrypt: src_len < POLY1305_DIGEST_SIZE, the
 *     decrypt-too-short branch of the internal crypt_oneshot helper - never
 *     exercised (every existing decrypt call uses a >= 16-byte ciphertext).
 *   - wc_XChaCha20Poly1305_Encrypt: dst_space < dst_len -> BUFFER_E - never
 *     exercised (every existing call sizes the output buffer generously).
 *   - internal crypt_oneshot helper: the ad_len/nonce_len/key_len >
 *     WOLFSSL_MAX_32BIT truncation-guard OR-chain - never exercised (every
 *     existing call uses in-range lengths); each operand's independence
 *     pair is shown on a 64-bit CPU (the only width where a size_t value
 *     can exceed WOLFSSL_MAX_32BIT).
 ******************************************************************************/
int test_wc_XChaCha20Poly1305_DecisionCoverage(void)
{
    EXPECT_DECLS;
#if defined(HAVE_POLY1305) && defined(HAVE_XCHACHA)
    static const byte key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
        0x80,0x81,0x82,0x83, 0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b, 0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93, 0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b, 0x9c,0x9d,0x9e,0x9f
    };
    static const byte nonce[XCHACHA20_POLY1305_AEAD_NONCE_SIZE] = {
        0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b, 0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53, 0x54,0x55,0x56,0x57
    };
    static const byte aad[12] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3, 0xc4,0xc5,0xc6,0xc7
    };
    static const byte plaintext[16] = {
        0x4c,0x61,0x64,0x69, 0x65,0x73,0x20,0x61,
        0x6e,0x64,0x20,0x47, 0x65,0x6e,0x74,0x73
    };
    ChaChaPoly_Aead aead;
    byte out[sizeof(plaintext) + POLY1305_DIGEST_SIZE];
    byte shortCt[8];
    byte small[4];

    XMEMSET(&aead,   0, sizeof(aead));
    XMEMSET(out,     0, sizeof(out));
    XMEMSET(shortCt, 0, sizeof(shortCt));
    XMEMSET(small,   0, sizeof(small));

    /* --- wc_XChaCha20Poly1305_Init: NULL aead. */
    ExpectIntEQ(wc_XChaCha20Poly1305_Init(NULL, aad, sizeof(aad),
        nonce, sizeof(nonce), key, sizeof(key), 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- wc_XChaCha20Poly1305_Init: ad == NULL, ad_len == 0 -> success. */
    ExpectIntEQ(wc_XChaCha20Poly1305_Init(&aead, NULL, 0,
        nonce, sizeof(nonce), key, sizeof(key), 1), 0);

    /* --- wc_XChaCha20Poly1305_Decrypt: src_len < POLY1305_DIGEST_SIZE. */
    ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(small, sizeof(small),
        shortCt, POLY1305_DIGEST_SIZE - 1, aad, sizeof(aad),
        nonce, sizeof(nonce), key, sizeof(key)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- wc_XChaCha20Poly1305_Encrypt: dst_space < dst_len -> BUFFER_E. */
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(plaintext),
        plaintext, sizeof(plaintext), aad, sizeof(aad),
        nonce, sizeof(nonce), key, sizeof(key)),
        WC_NO_ERR_TRACE(BUFFER_E));

    /* --- Internal crypt_oneshot helper's length sanity check:
     * "(ad_len > WOLFSSL_MAX_32BIT) || (nonce_len > WOLFSSL_MAX_32BIT) ||
     * (key_len > WOLFSSL_MAX_32BIT)". Only expressible where size_t is
     * wider than 32 bits (on a 32-bit CPU no size_t value can exceed
     * WOLFSSL_MAX_32BIT, so the decision is a permanent, always-false
     * residual there). Each call flips exactly one operand above
     * WOLFSSL_MAX_32BIT while the other two stay at their valid, in-range
     * sizes; the "all in range" false side is exercised throughout the
     * rest of this file's successful Encrypt/Decrypt calls. None of these
     * huge lengths are ever dereferenced: the check fires before the ad/
     * nonce/key buffers are touched. */
#if defined(WC_64BIT_CPU)
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(out),
        plaintext, sizeof(plaintext), aad, (size_t)WOLFSSL_MAX_32BIT + 1,
        nonce, sizeof(nonce), key, sizeof(key)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(out),
        plaintext, sizeof(plaintext), aad, sizeof(aad),
        nonce, (size_t)WOLFSSL_MAX_32BIT + 1, key, sizeof(key)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(out, sizeof(out),
        plaintext, sizeof(plaintext), aad, sizeof(aad),
        nonce, sizeof(nonce), key, (size_t)WOLFSSL_MAX_32BIT + 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif /* WC_64BIT_CPU */
#endif
    return EXPECT_RESULT();
} /* END test_wc_XChaCha20Poly1305_DecisionCoverage */

/*
 * XChaCha20-Poly1305 large-buffer round trip: forces the internal
 * crypt_oneshot helper's 16384-byte chunking ternary
 * "(src_len_rem > 16384) ? 16384 : (word32)src_len_rem" true branch (input
 * > 16384 bytes -> more than one wc_Chacha_Process/wc_Poly1305Update
 * iteration), never hit by any other test in the suite (all use buffers
 * well under 16 KB).
 */
int test_wc_XChaCha20Poly1305_LargeBuffer(void)
{
    EXPECT_DECLS;
#if defined(HAVE_POLY1305) && defined(HAVE_XCHACHA)
    static const byte key[CHACHA20_POLY1305_AEAD_KEYSIZE] = {
        0x80,0x81,0x82,0x83, 0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b, 0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93, 0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b, 0x9c,0x9d,0x9e,0x9f
    };
    static const byte nonce[XCHACHA20_POLY1305_AEAD_NONCE_SIZE] = {
        0x40,0x41,0x42,0x43, 0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b, 0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53, 0x54,0x55,0x56,0x57
    };
    static const byte aad[12] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3, 0xc4,0xc5,0xc6,0xc7
    };
    #define LARGE_BUF_LEN (16384 + 256)
    byte* plain;
    byte* ct;
    byte* back;
    word32 i;

    plain = (byte*)XMALLOC(LARGE_BUF_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ct    = (byte*)XMALLOC(LARGE_BUF_LEN + POLY1305_DIGEST_SIZE, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
    back  = (byte*)XMALLOC(LARGE_BUF_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(plain);
    ExpectNotNull(ct);
    ExpectNotNull(back);

    if (plain != NULL && ct != NULL && back != NULL) {
        for (i = 0; i < LARGE_BUF_LEN; i++)
            plain[i] = (byte)i;
        XMEMSET(ct,   0, LARGE_BUF_LEN + POLY1305_DIGEST_SIZE);
        XMEMSET(back, 0, LARGE_BUF_LEN);

        ExpectIntEQ(wc_XChaCha20Poly1305_Encrypt(ct,
            LARGE_BUF_LEN + POLY1305_DIGEST_SIZE, plain, LARGE_BUF_LEN,
            aad, sizeof(aad), nonce, sizeof(nonce), key, sizeof(key)), 0);
        ExpectIntEQ(wc_XChaCha20Poly1305_Decrypt(back, LARGE_BUF_LEN,
            ct, LARGE_BUF_LEN + POLY1305_DIGEST_SIZE,
            aad, sizeof(aad), nonce, sizeof(nonce), key, sizeof(key)), 0);
        ExpectBufEQ(back, plain, LARGE_BUF_LEN);
    }

    XFREE(plain, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(ct,    NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(back,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #undef LARGE_BUF_LEN
#endif
    return EXPECT_RESULT();
} /* END test_wc_XChaCha20Poly1305_LargeBuffer */

/*
 * Large-message coverage for the AVX-512 + IFMA single-pass stitch, which the
 * one-shot Encrypt, Encrypt_ex, Decrypt_ex and streaming paths all dispatch to
 * at sz >= CHACHA20_POLY1305_STITCH_MIN (default 4096) on capable CPUs.  No
 * other test reaches 4096 bytes, so on AVX-512/IFMA hardware this is the only
 * exercise of the stitch kernel, its scalar sub-1024 tail, and the AAD fold.
 * On CPUs without AVX-512/IFMA every call transparently uses the two-pass path,
 * so the test still validates (round-trips) but does not reach the stitch.
 *
 * Sizes span the sub-bands the stitch splits on: exact 1024-multiples (no
 * tail), non-multiples (stitch + scalar tail), and both AAD present / absent
 * (the poly1305_fold_avx512ifma AAD fold).  Correctness is cross-checked three
 * independent ways: the one-shot two-pass Decrypt round-trips the one-shot
 * (stitch) ciphertext; Encrypt_ex must reproduce the one-shot ciphertext+tag
 * byte-for-byte; and Decrypt_ex (the decrypt stitch, decrypt-then-verify)
 * recovers the plaintext and, on a corrupted tag, returns MAC_CMP_FAILED_E with
 * a zeroized output (no plaintext released though the stitch decrypts first).
 */
int test_wc_ChaCha20Poly1305_LargeMessage(void)
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
    /* >= STITCH_MIN: exact 1024-multiples (4096/8192/16384) and tails
     * (4097 -> 1-byte tail, 5000 -> 904-byte tail). */
    static const word32 sizes[] = { 4096, 4097, 5000, 8192, 16384 };
    static const word32 aadLens[] = { 0, 12 };
    #define BIG_MSG_LEN 16384
    byte* pt = NULL;
    byte* ct = NULL;
    byte* out = NULL;
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte tag2[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    ChaCha chacha;
    Poly1305 poly;
    word32 a;
    word32 s;

    pt  = (byte*)XMALLOC(BIG_MSG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ct  = (byte*)XMALLOC(BIG_MSG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    out = (byte*)XMALLOC(BIG_MSG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pt);
    ExpectNotNull(ct);
    ExpectNotNull(out);

    for (a = 0; a < (word32)(sizeof(aadLens) / sizeof(aadLens[0])); a++) {
        word32 aadLen = aadLens[a];
        for (s = 0; s < (word32)(sizeof(sizes) / sizeof(sizes[0])); s++) {
            word32 sz = sizes[s];
            word32 i;

            if (pt == NULL || ct == NULL || out == NULL)
                break;
            for (i = 0; i < sz; i++)
                pt[i] = (byte)(i * 3 + 1);

            /* One-shot Encrypt: IFMA stitch when sz >= STITCH_MIN. */
            XMEMSET(ct, 0, sz);
            XMEMSET(tag, 0, sizeof(tag));
            ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, aadLen,
                pt, sz, ct, tag), 0);

            /* Round-trip via the independent two-pass one-shot Decrypt: proves
             * the encrypt stitch produced a correct ciphertext AND tag. */
            XMEMSET(out, 0, sz);
            ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, aadLen,
                ct, sz, tag, out), 0);
            ExpectBufEQ(out, pt, sz);

            /* Encrypt_ex must reproduce the one-shot ciphertext + tag. */
            ExpectIntEQ(wc_Chacha_SetKey(&chacha, key, sizeof(key)), 0);
            XMEMSET(out, 0, sz);
            XMEMSET(tag2, 0, sizeof(tag2));
            ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(&chacha, &poly, out, pt,
                sz, iv, tag2, aad, aadLen), 0);
            ExpectBufEQ(out, ct, sz);
            ExpectBufEQ(tag2, tag, sizeof(tag2));

            /* Decrypt_ex: the decrypt stitch (decrypt-then-verify) must recover
             * the plaintext with a valid tag. */
            ExpectIntEQ(wc_Chacha_SetKey(&chacha, key, sizeof(key)), 0);
            XMEMSET(out, 0, sz);
            ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, &poly, out, ct,
                sz, iv, tag, aad, aadLen), 0);
            ExpectBufEQ(out, pt, sz);

            /* Bad tag: the stitch decrypts before checking the tag, so verify
             * Decrypt_ex both reports the failure and zeroizes the output. */
            tag[0] ^= 0xff;
            ExpectIntEQ(wc_Chacha_SetKey(&chacha, key, sizeof(key)), 0);
            XMEMSET(out, 0xa5, sz);
            ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, &poly, out, ct,
                sz, iv, tag, aad, aadLen),
                WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
            ExpectIntEQ(out[0], 0);
            ExpectIntEQ(out[sz / 2], 0);
            ExpectIntEQ(out[sz - 1], 0);
            tag[0] ^= 0xff;
        }
    }

    XFREE(pt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(ct,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #undef BIG_MSG_LEN
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_LargeMessage */

/*
 * Small-message coverage WITH a non-empty AAD.  The fused single-call asm
 * kernels (chacha20_poly1305_small_enc / _dec) handle sz <= 64 on AVX2 CPUs and
 * fold the AAD into Poly1305 inside assembly.  No existing test drives that
 * path with AAD: the KAT vectors are > 64 bytes, and MonteCarlo used NULL/0
 * AAD - so the in-kernel AAD fold (the exact code the Windows stack-offset
 * defects corrupt) was never executed.  This is deterministic across the whole
 * small band including the sz == 64 boundary.
 *
 * The streaming API does NOT use the short/small path, so it is an independent
 * reference: small_enc must reproduce its ciphertext + tag byte-for-byte.  The
 * round-trip then recovers the plaintext via small_dec, and a corrupted tag
 * must return MAC_CMP_FAILED_E with a fully zeroized output (small_dec decrypts
 * before it verifies).  On CPUs without AVX2 the same calls use the C fallback,
 * so the test still validates but does not reach the asm kernel.
 */
int test_wc_ChaCha20Poly1305_SmallWithAad(void)
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
    static const byte aad[20] = {
        0x50,0x51,0x52,0x53, 0xc0,0xc1,0xc2,0xc3, 0xc4,0xc5,0xc6,0xc7,
        0xf0,0xf1,0xf2,0xf3, 0xf4,0xf5,0xf6,0xf7
    };
    /* small band: the AVX2 kernel is used for sz <= 64 - cover 1, mid, the
     * boundary at 64, and one just past it as a control. */
    static const word32 sizes[] = { 1, 16, 32, 63, 64, 65 };
    static const word32 aadLens[] = { 0, 1, 12, 20 };
    byte pt[65];
    byte ct[65];
    byte ref[65];
    byte back[65];
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte tagRef[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    ChaChaPoly_Aead aead;
    word32 a;
    word32 s;
    word32 i;

    XMEMSET(&aead, 0, sizeof(aead));

    for (a = 0; a < (word32)(sizeof(aadLens) / sizeof(aadLens[0])); a++) {
        word32 aadLen = aadLens[a];
        for (s = 0; s < (word32)(sizeof(sizes) / sizeof(sizes[0])); s++) {
            word32 sz = sizes[s];

            for (i = 0; i < sz; i++)
                pt[i] = (byte)(i * 7 + 2);

            /* One-shot Encrypt: sz <= 64 dispatches to small_enc, which folds
             * the AAD in asm. */
            XMEMSET(ct, 0, sizeof(ct));
            XMEMSET(tag, 0, sizeof(tag));
            ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, aadLen,
                pt, sz, ct, tag), 0);

            /* Independent reference via the streaming API (never the small
             * path): validates small_enc + AAD fold against the two-pass. */
            ExpectIntEQ(wc_ChaCha20Poly1305_Init(&aead, key, iv,
                CHACHA20_POLY1305_AEAD_ENCRYPT), 0);
            if (aadLen > 0)
                ExpectIntEQ(wc_ChaCha20Poly1305_UpdateAad(&aead, aad, aadLen),
                    0);
            XMEMSET(ref, 0, sizeof(ref));
            ExpectIntEQ(wc_ChaCha20Poly1305_UpdateData(&aead, pt, ref, sz), 0);
            ExpectIntEQ(wc_ChaCha20Poly1305_Final(&aead, tagRef), 0);
            ExpectBufEQ(ct, ref, sz);
            ExpectBufEQ(tag, tagRef, sizeof(tag));

            /* Round-trip: small_dec recovers the plaintext from the reference
             * ciphertext. */
            XMEMSET(back, 0, sizeof(back));
            ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, aadLen,
                ref, sz, tagRef, back), 0);
            ExpectBufEQ(back, pt, sz);

            /* Bad tag: small_dec decrypts before verifying, so Decrypt must
             * both report the failure and zeroize the whole output. */
            tag[0] ^= 0xff;
            XMEMSET(back, 0xa5, sizeof(back));
            ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, aadLen,
                ct, sz, tag, back), WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
            for (i = 0; i < sz; i++)
                ExpectIntEQ(back[i], 0);
            tag[0] ^= 0xff;
        }
    }
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_SmallWithAad */

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
/* Streaming AEAD over one message, splitting the data into a first chunk of
 * 'first' bytes then 'rest'-byte chunks (both clamped to what remains).  enc
 * selects encrypt vs decrypt; the computed/authentication tag is returned in
 * 'tag' (for decrypt the caller compares it against the received tag). */
static int cp_stream(int enc, const byte* key, const byte* iv, const byte* aad,
    word32 aadLen, const byte* in, word32 sz, word32 first, word32 rest,
    byte* out, byte* tag)
{
    ChaChaPoly_Aead aead;
    word32 off;
    word32 n;
    int ret;

    XMEMSET(&aead, 0, sizeof(aead));
    ret = wc_ChaCha20Poly1305_Init(&aead, key, iv, enc ?
        CHACHA20_POLY1305_AEAD_ENCRYPT : CHACHA20_POLY1305_AEAD_DECRYPT);
    if (ret == 0 && aadLen > 0)
        ret = wc_ChaCha20Poly1305_UpdateAad(&aead, aad, aadLen);
    off = 0;
    while (ret == 0 && off < sz) {
        n = (off == 0) ? first : rest;
        if (n > sz - off)
            n = sz - off;
        ret = wc_ChaCha20Poly1305_UpdateData(&aead, in + off, out + off, n);
        off += n;
    }
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_Final(&aead, tag);
    return ret;
}
#endif

/*
 * Large-message coverage of the streaming UpdateData IFMA stitch.  UpdateData
 * grows two AVX-512/IFMA paths that both need dataLen >= STITCH_MIN (4096): the
 * first-chunk stitch entry - which, when AAD was buffered by the vector path
 * (< 128 bytes, leftover > 0), COPIES it to a 128-byte stack buffer and
 * re-hashes it through the scalar path - and the per-chunk stitch gated on
 * (dataLen & 63) == 0.  Every existing streaming test uses <= 64-byte chunks,
 * so none of this ran.  The buffered-AAD re-hash is the highest-value case: a
 * leftover/pad miscount there yields a wrong tag.
 *
 * The streaming API is chunk-invariant by contract, so 256-byte-chunk streaming
 * (which never reaches STITCH_MIN, hence pure two-pass) is the reference every
 * stitched chunking must match.  Splits exercise: a single large call (entry +
 * AAD re-hash + full bulk); a 4096 first chunk (2nd chunk 64-aligned -> the
 * per-chunk stitch fires); and a 4128 first chunk (2nd chunk NOT 64-aligned ->
 * the guard's false branch, two-pass).  AAD lengths cover none, buffered
 * (12/120 -> re-hash) and >= 128 (200 -> vector-processed, stitch entry
 * blocked).  A two-pass one-shot Decrypt independently round-trips each result.
 */
int test_wc_ChaCha20Poly1305_StreamLarge(void)
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
    byte aad[200];
    static const word32 aadLens[] = { 0, 12, 120, 200 };
    /* { first-chunk, rest-chunk } data splits. */
    static const word32 splits[][2] = {
        { 12288, 12288 },   /* one UpdateData call */
        { 4096,  12288 },   /* 64-aligned first chunk -> 2nd chunk stitches */
        { 4128,  12288 }    /* unaligned first chunk  -> 2nd chunk two-pass */
    };
    #define SL_LEN 12288
    byte* pt = NULL;
    byte* ct = NULL;
    byte* ref = NULL;
    byte* back = NULL;
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte tagRef[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte calc[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    word32 a;
    word32 sp;
    word32 i;

    for (i = 0; i < sizeof(aad); i++)
        aad[i] = (byte)(i + 0x30);

    pt   = (byte*)XMALLOC(SL_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ct   = (byte*)XMALLOC(SL_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ref  = (byte*)XMALLOC(SL_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    back = (byte*)XMALLOC(SL_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pt);
    ExpectNotNull(ct);
    ExpectNotNull(ref);
    ExpectNotNull(back);

    if (pt != NULL && ct != NULL && ref != NULL && back != NULL) {
        for (i = 0; i < SL_LEN; i++)
            pt[i] = (byte)(i * 5 + 3);

        for (a = 0; a < (word32)(sizeof(aadLens) / sizeof(aadLens[0]))
                && EXPECT_SUCCESS(); a++) {
            word32 aadLen = aadLens[a];

            /* Reference: 256-byte chunks stay below STITCH_MIN -> two-pass. */
            XMEMSET(ref, 0, SL_LEN);
            ExpectIntEQ(cp_stream(1, key, iv, aad, aadLen, pt, SL_LEN, 256, 256,
                ref, tagRef), 0);

            for (sp = 0; sp < (word32)(sizeof(splits) / sizeof(splits[0]))
                    && EXPECT_SUCCESS(); sp++) {
                /* Stitched streaming encrypt must match the two-pass ref. */
                XMEMSET(ct, 0, SL_LEN);
                ExpectIntEQ(cp_stream(1, key, iv, aad, aadLen, pt, SL_LEN,
                    splits[sp][0], splits[sp][1], ct, tag), 0);
                ExpectBufEQ(ct, ref, SL_LEN);
                ExpectBufEQ(tag, tagRef, sizeof(tag));

                /* Streaming decrypt (decrypt stitch) recovers the plaintext and
                 * computes the matching tag. */
                XMEMSET(back, 0, SL_LEN);
                ExpectIntEQ(cp_stream(0, key, iv, aad, aadLen, ct, SL_LEN,
                    splits[sp][0], splits[sp][1], back, calc), 0);
                ExpectIntEQ(wc_ChaCha20Poly1305_CheckTag(tag, calc), 0);
                ExpectBufEQ(back, pt, SL_LEN);
            }

            /* Independent: the two-pass one-shot Decrypt round-trips it. */
            XMEMSET(back, 0, SL_LEN);
            ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt(key, iv, aad, aadLen,
                ref, SL_LEN, tagRef, back), 0);
            ExpectBufEQ(back, pt, SL_LEN);
        }
    }

    XFREE(pt,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(ct,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(ref,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(back, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #undef SL_LEN
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_StreamLarge */

/*
 * Direct, full-coverage test of the new pre-keyed one-shot APIs
 * wc_ChaCha20Poly1305_Encrypt_ex / _Decrypt_ex (the TLS-record analogue of
 * wc_AesGcmEncrypt/Decrypt on a keyed context).  Exercises every dispatch band
 * the _ex path selects on - the sz <= 64 small asm kernel, the 64 < sz <= 192
 * short C path, the 192 < sz < 4096 two-pass, and the sz >= 4096 IFMA stitch
 * (+ sub-1024 tail) - each with AAD absent, buffered, and larger, and both
 * separate and in-place (out == in) buffers.  Correctness is anchored to the
 * trusted one-shot wc_ChaCha20Poly1305_Encrypt, which _ex must reproduce
 * byte-for-byte regardless of which internal path either takes.  Also covers
 * Decrypt_ex tag verification + output zeroization on a bad tag, the keyed-
 * context reuse pattern (SetKey once, vary the nonce per record), and the full
 * argument-validation matrix.
 */
int test_wc_ChaCha20Poly1305_Ex(void)
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
    byte aad[64];
    /* one size in each _ex dispatch band, plus the band boundaries. */
    static const word32 sizes[] =
        { 0, 1, 64, 100, 192, 193, 1024, 4096, 5000 };
    static const word32 aadLens[] = { 0, 12, 64 };
    #define EX_MAX 5000
    ChaCha chacha;
    Poly1305 poly;
    byte* pt = NULL;
    byte* ct = NULL;
    byte* ref = NULL;
    byte* out = NULL;
    byte* tmp = NULL;
    byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    byte tagRef[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    word32 a;
    word32 s;
    word32 i;

    for (i = 0; i < sizeof(aad); i++)
        aad[i] = (byte)(i + 0xa0);

    pt  = (byte*)XMALLOC(EX_MAX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ct  = (byte*)XMALLOC(EX_MAX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ref = (byte*)XMALLOC(EX_MAX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    out = (byte*)XMALLOC(EX_MAX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    tmp = (byte*)XMALLOC(EX_MAX, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pt);
    ExpectNotNull(ct);
    ExpectNotNull(ref);
    ExpectNotNull(out);
    ExpectNotNull(tmp);

    if (pt != NULL && ct != NULL && ref != NULL && out != NULL &&
            tmp != NULL) {
        for (i = 0; i < EX_MAX; i++)
            pt[i] = (byte)(i * 11 + 5);

        for (a = 0; a < (word32)(sizeof(aadLens) / sizeof(aadLens[0]))
                && EXPECT_SUCCESS(); a++) {
            word32 aadLen = aadLens[a];

            for (s = 0; s < (word32)(sizeof(sizes) / sizeof(sizes[0]))
                    && EXPECT_SUCCESS(); s++) {
                word32 sz = sizes[s];

                /* Encrypt_ex on a pre-keyed context. */
                ExpectIntEQ(wc_Chacha_SetKey(&chacha, key, sizeof(key)), 0);
                XMEMSET(ct, 0, EX_MAX);
                XMEMSET(tag, 0, sizeof(tag));
                ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(&chacha, &poly, ct,
                    pt, sz, iv, tag, aad, aadLen), 0);

                /* Must match the trusted one-shot Encrypt byte-for-byte. */
                XMEMSET(ref, 0, EX_MAX);
                ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt(key, iv, aad, aadLen,
                    pt, sz, ref, tagRef), 0);
                ExpectBufEQ(ct, ref, sz);
                ExpectBufEQ(tag, tagRef, sizeof(tag));

                /* Encrypt_ex in place (out == in). */
                XMEMCPY(tmp, pt, sz);
                ExpectIntEQ(wc_Chacha_SetKey(&chacha, key, sizeof(key)), 0);
                ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(&chacha, &poly, tmp,
                    tmp, sz, iv, tag, aad, aadLen), 0);
                ExpectBufEQ(tmp, ct, sz);

                /* Decrypt_ex round-trip, separate buffers. */
                ExpectIntEQ(wc_Chacha_SetKey(&chacha, key, sizeof(key)), 0);
                XMEMSET(out, 0, EX_MAX);
                ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, &poly, out,
                    ct, sz, iv, tag, aad, aadLen), 0);
                ExpectBufEQ(out, pt, sz);

                /* Decrypt_ex in place (out == in). */
                XMEMCPY(tmp, ct, sz);
                ExpectIntEQ(wc_Chacha_SetKey(&chacha, key, sizeof(key)), 0);
                ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, &poly, tmp,
                    tmp, sz, iv, tag, aad, aadLen), 0);
                ExpectBufEQ(tmp, pt, sz);

                /* Bad tag: MAC_CMP_FAILED_E and the whole output zeroized. */
                tag[0] ^= 0xff;
                ExpectIntEQ(wc_Chacha_SetKey(&chacha, key, sizeof(key)), 0);
                XMEMSET(out, 0xa5, EX_MAX);
                ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, &poly, out,
                    ct, sz, iv, tag, aad, aadLen),
                    WC_NO_ERR_TRACE(MAC_CMP_FAILED_E));
                for (i = 0; i < sz; i++)
                    ExpectIntEQ(out[i], 0);
                tag[0] ^= 0xff;
            }
        }

        /* Keyed-context reuse: SetKey once, encrypt several records that differ
         * only by nonce (the intended TLS usage), each decrypting back. */
        ExpectIntEQ(wc_Chacha_SetKey(&chacha, key, sizeof(key)), 0);
        for (i = 0; i < 4 && EXPECT_SUCCESS(); i++) {
            byte nonce[CHACHA20_POLY1305_AEAD_IV_SIZE];
            ChaCha chachaDec;
            word32 sz = 200 + i * 37;

            XMEMCPY(nonce, iv, sizeof(nonce));
            nonce[0] = (byte)i;                  /* vary the nonce per record */
            XMEMSET(ct, 0, EX_MAX);
            ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(&chacha, &poly, ct, pt,
                sz, nonce, tag, aad, 12), 0);
            ExpectIntEQ(wc_Chacha_SetKey(&chachaDec, key, sizeof(key)), 0);
            XMEMSET(out, 0, EX_MAX);
            ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chachaDec, &poly, out,
                ct, sz, nonce, tag, aad, 12), 0);
            ExpectBufEQ(out, pt, sz);
        }

        /* Argument validation - Encrypt_ex. */
        ExpectIntEQ(wc_Chacha_SetKey(&chacha, key, sizeof(key)), 0);
        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(NULL, &poly, ct, pt, 64,
            iv, tag, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(&chacha, NULL, ct, pt, 64,
            iv, tag, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(&chacha, &poly, ct, pt, 64,
            NULL, tag, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(&chacha, &poly, ct, pt, 64,
            iv, NULL, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(&chacha, &poly, ct, NULL, 64,
            iv, tag, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(&chacha, &poly, NULL, pt, 64,
            iv, tag, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Encrypt_ex(&chacha, &poly, ct, pt, 64,
            iv, tag, NULL, 12), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Argument validation - Decrypt_ex. */
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(NULL, &poly, out, ct, 64,
            iv, tag, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, NULL, out, ct, 64,
            iv, tag, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, &poly, out, ct, 64,
            NULL, tag, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, &poly, out, ct, 64,
            iv, NULL, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, &poly, out, NULL,
            64, iv, tag, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, &poly, NULL, ct, 64,
            iv, tag, aad, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_ChaCha20Poly1305_Decrypt_ex(&chacha, &poly, out, ct, 64,
            iv, tag, NULL, 12), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

    XFREE(pt,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(ct,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(ref, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #undef EX_MAX
#endif
    return EXPECT_RESULT();
} /* END test_wc_ChaCha20Poly1305_Ex */
