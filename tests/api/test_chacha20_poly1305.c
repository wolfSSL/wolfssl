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
