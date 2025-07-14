/* test_chacha20_poly1305.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

