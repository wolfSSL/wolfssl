/* test_ascon.c
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

#include <wolfssl/wolfcrypt/ascon.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/test_ascon.h>

#ifdef HAVE_ASCON
#include <tests/api/test_ascon_kats.h>
#endif

int test_ascon_hash256(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ASCON
    byte msg[1024];
    byte mdOut[ASCON_HASH256_SZ];
    const size_t test_rounds = sizeof(msg) + 1; /* +1 to test 0-len msg */
    wc_AsconHash256* asconHash = NULL;
    word32 i;

    ExpectIntEQ(XELEM_CNT(ascon_hash256_output), test_rounds);

    /* init msg buffer */
    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (byte)i;

    ExpectNotNull(asconHash = wc_AsconHash256_New());

    for (i = 0; i < test_rounds && EXPECT_SUCCESS(); i++) {
        XMEMSET(mdOut, 0, sizeof(mdOut));
        ExpectIntEQ(wc_AsconHash256_Init(asconHash), 0);
        ExpectIntEQ(wc_AsconHash256_Update(asconHash, msg, i), 0);
        ExpectIntEQ(wc_AsconHash256_Final(asconHash, mdOut), 0);
        ExpectBufEQ(mdOut, ascon_hash256_output[i], ASCON_HASH256_SZ);
        wc_AsconHash256_Clear(asconHash);
    }

    /* Test separated update */
    for (i = 0; i < test_rounds && EXPECT_SUCCESS(); i++) {
        word32 half_i = i / 2;
        XMEMSET(mdOut, 0, sizeof(mdOut));
        ExpectIntEQ(wc_AsconHash256_Init(asconHash), 0);
        ExpectIntEQ(wc_AsconHash256_Update(asconHash, msg, half_i), 0);
        ExpectIntEQ(wc_AsconHash256_Update(asconHash, msg + half_i,
                                           i - half_i), 0);
        ExpectIntEQ(wc_AsconHash256_Final(asconHash, mdOut), 0);
        ExpectBufEQ(mdOut, ascon_hash256_output[i], ASCON_HASH256_SZ);
        wc_AsconHash256_Clear(asconHash);
    }

    wc_AsconHash256_Free(asconHash);
#endif
    return EXPECT_RESULT();
}

int test_ascon_aead128(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ASCON
    word32 i;
    wc_AsconAEAD128* asconAEAD = NULL;

    ExpectNotNull(asconAEAD = wc_AsconAEAD128_New());

    for (i = 0; i < XELEM_CNT(ascon_aead128_kat); i++) {
        byte key[ASCON_AEAD128_KEY_SZ];
        byte nonce[ASCON_AEAD128_NONCE_SZ];
        byte pt[32]; /* longest plaintext we test is 32 bytes */
        word32 ptSz;
        byte ad[32]; /* longest AD we test is 32 bytes */
        word32 adSz;
        byte ct[48]; /* longest ciphertext we test is 32 bytes + 16 bytes tag */
        word32 ctSz;
        word32 j;
        byte tag[ASCON_AEAD128_TAG_SZ];
        byte buf[32]; /* longest buffer we test is 32 bytes */

        XMEMSET(key, 0, sizeof(key));
        XMEMSET(nonce, 0, sizeof(nonce));
        XMEMSET(pt, 0, sizeof(pt));
        XMEMSET(ad, 0, sizeof(ad));
        XMEMSET(ct, 0, sizeof(ct));
        XMEMSET(tag, 0, sizeof(tag));

        /* Convert HEX strings to byte stream */
        for (j = 0; ascon_aead128_kat[i][0][j] != '\0'; j += 2) {
            key[j/2] = HexCharToByte(ascon_aead128_kat[i][0][j]) << 4 |
                       HexCharToByte(ascon_aead128_kat[i][0][j+1]);
        }
        for (j = 0; ascon_aead128_kat[i][1][j] != '\0'; j += 2) {
            nonce[j/2] = HexCharToByte(ascon_aead128_kat[i][1][j]) << 4 |
                         HexCharToByte(ascon_aead128_kat[i][1][j+1]);
        }
        for (j = 0; ascon_aead128_kat[i][2][j] != '\0'; j += 2) {
            pt[j/2] = HexCharToByte(ascon_aead128_kat[i][2][j]) << 4 |
                      HexCharToByte(ascon_aead128_kat[i][2][j+1]);
        }
        ptSz = j/2;
        for (j = 0; ascon_aead128_kat[i][3][j] != '\0'; j += 2) {
            ad[j/2] = HexCharToByte(ascon_aead128_kat[i][3][j]) << 4 |
                      HexCharToByte(ascon_aead128_kat[i][3][j+1]);
        }
        adSz = j/2;
        for (j = 0; ascon_aead128_kat[i][4][j] != '\0'; j += 2) {
            ct[j/2] = HexCharToByte(ascon_aead128_kat[i][4][j]) << 4 |
                      HexCharToByte(ascon_aead128_kat[i][4][j+1]);
        }
        ctSz = j/2 - ASCON_AEAD128_TAG_SZ;

        for (j = 0; j < 4; j++) {
            ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
            ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
            ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
            ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, ad, adSz), 0);
            if (j == 0) {
                /* Encryption test */
                ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, buf, pt,
                            ptSz), 0);
                ExpectBufEQ(buf, ct, ptSz);
                ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(asconAEAD, tag), 0);
                ExpectBufEQ(tag, ct + ptSz, ASCON_AEAD128_TAG_SZ);
            }
            else if (j == 1) {
                /* Decryption test */
                ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, buf, ct,
                            ctSz), 0);
                ExpectBufEQ(buf, pt, ctSz);
                ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, ct + ctSz),
                            0);
            }
            else if (j == 2) {
                /* Split encryption test */
                ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, buf, pt,
                        ptSz / 2), 0);
                ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD,
                        buf + (ptSz/2), pt + (ptSz/2), ptSz - (ptSz/2)), 0);
                ExpectBufEQ(buf, ct, ptSz);
                ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(asconAEAD, tag), 0);
                ExpectBufEQ(tag, ct + ptSz, ASCON_AEAD128_TAG_SZ);
            }
            else if (j == 3) {
                /* Split decryption test */
                ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, buf, ct,
                        ctSz / 2), 0);
                ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD,
                        buf + (ctSz/2), ct + (ctSz/2), ctSz - (ctSz/2)), 0);
                ExpectBufEQ(buf, pt, ctSz);
                ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, ct + ctSz),
                        0);
            }
            wc_AsconAEAD128_Clear(asconAEAD);
        }
    }

    wc_AsconAEAD128_Free(asconAEAD);
#endif
    return EXPECT_RESULT();
}

/*
 * Ascon-AEAD128 AEAD edge cases:
 *   - invalid auth tag rejection  (DecryptFinal with wrong tag -> ASCON_AUTH_E)
 *   - empty plaintext with empty AAD  (KAT[0])
 *   - empty plaintext with non-empty AAD  (KAT[1])
 *
 * KAT vectors are from the Ascon reference implementation:
 *   https://github.com/ascon/ascon-c
 */
int test_ascon_aead128_edge_cases(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ASCON
    /* Shared key and nonce for all sub-tests (same as KAT[0..N]) */
    static const byte key[ASCON_AEAD128_KEY_SZ] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    static const byte nonce[ASCON_AEAD128_NONCE_SZ] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    /* KAT[0]: PT="", AD="" -> CT = tag only */
    static const byte expTag0[ASCON_AEAD128_TAG_SZ] = {
        0x44, 0x27, 0xD6, 0x4B, 0x8E, 0x1E, 0x14, 0x51,
        0xFC, 0x44, 0x59, 0x60, 0xF0, 0x83, 0x9B, 0xB0
    };
    /* KAT[1]: PT="", AD="00" -> CT = tag only */
    static const byte ad1[1]  = { 0x00 };
    static const byte expTag1[ASCON_AEAD128_TAG_SZ] = {
        0x10, 0x3A, 0xB7, 0x9D, 0x91, 0x3A, 0x03, 0x21,
        0x28, 0x77, 0x15, 0xA9, 0x79, 0xBB, 0x85, 0x85
    };
    wc_AsconAEAD128* asconAEAD = NULL;
    byte tagBuf[ASCON_AEAD128_TAG_SZ];
    byte badTag[ASCON_AEAD128_TAG_SZ];
    byte dummy[1]; /* non-NULL placeholder for 0-length pt/ct args */

    ExpectNotNull(asconAEAD = wc_AsconAEAD128_New());

    /* ------------------------------------------------------------------ */
    /* 1. Empty plaintext + empty AAD (KAT[0])                            */
    /* ------------------------------------------------------------------ */

    /* Encrypt and verify tag against KAT */
    ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, dummy, 0), 0);
    ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, dummy, dummy, 0), 0);
    XMEMSET(tagBuf, 0, sizeof(tagBuf));
    ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(asconAEAD, tagBuf), 0);
    ExpectBufEQ(tagBuf, expTag0, ASCON_AEAD128_TAG_SZ);
    wc_AsconAEAD128_Clear(asconAEAD);

    /* Decrypt with correct tag -> success */
    ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, dummy, 0), 0);
    ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, dummy, dummy, 0), 0);
    ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, expTag0), 0);
    wc_AsconAEAD128_Clear(asconAEAD);

    /* Decrypt with wrong tag -> ASCON_AUTH_E */
    XMEMCPY(badTag, expTag0, ASCON_AEAD128_TAG_SZ);
    badTag[0] ^= 0xff;
    ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, dummy, 0), 0);
    ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, dummy, dummy, 0), 0);
    ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, badTag),
        WC_NO_ERR_TRACE(ASCON_AUTH_E));
    wc_AsconAEAD128_Clear(asconAEAD);

    /* ------------------------------------------------------------------ */
    /* 2. Empty plaintext + non-empty AAD (KAT[1], AD = {0x00})           */
    /* ------------------------------------------------------------------ */

    /* Encrypt and verify tag against KAT */
    ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, ad1, sizeof(ad1)), 0);
    ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, dummy, dummy, 0), 0);
    XMEMSET(tagBuf, 0, sizeof(tagBuf));
    ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(asconAEAD, tagBuf), 0);
    ExpectBufEQ(tagBuf, expTag1, ASCON_AEAD128_TAG_SZ);
    wc_AsconAEAD128_Clear(asconAEAD);

    /* Decrypt with correct tag -> success */
    ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, ad1, sizeof(ad1)), 0);
    ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, dummy, dummy, 0), 0);
    ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, expTag1), 0);
    wc_AsconAEAD128_Clear(asconAEAD);

    /* Decrypt with wrong tag -> ASCON_AUTH_E */
    XMEMCPY(badTag, expTag1, ASCON_AEAD128_TAG_SZ);
    badTag[0] ^= 0xff;
    ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, ad1, sizeof(ad1)), 0);
    ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, dummy, dummy, 0), 0);
    ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, badTag),
        WC_NO_ERR_TRACE(ASCON_AUTH_E));
    wc_AsconAEAD128_Clear(asconAEAD);

    /* ------------------------------------------------------------------ */
    /* 3. Non-empty plaintext: invalid tag rejection                       */
    /* ------------------------------------------------------------------ */
    {
        static const byte pt[] = { 0x00 };
        byte ct[sizeof(pt)];
        byte encTag[ASCON_AEAD128_TAG_SZ];

        /* Encrypt one byte */
        XMEMSET(ct,     0, sizeof(ct));
        XMEMSET(encTag, 0, sizeof(encTag));
        ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, dummy, 0), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, ct, pt,
            sizeof(pt)), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(asconAEAD, encTag), 0);
        wc_AsconAEAD128_Clear(asconAEAD);

        /* Decrypt with correct tag -> success */
        ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, dummy, 0), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, dummy, ct,
            sizeof(ct)), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, encTag), 0);
        wc_AsconAEAD128_Clear(asconAEAD);

        /* Decrypt with tampered tag -> ASCON_AUTH_E */
        encTag[ASCON_AEAD128_TAG_SZ - 1] ^= 0xff;
        ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, dummy, 0), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, dummy, ct,
            sizeof(ct)), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, encTag),
            WC_NO_ERR_TRACE(ASCON_AUTH_E));
        wc_AsconAEAD128_Clear(asconAEAD);
    }

    wc_AsconAEAD128_Free(asconAEAD);
#endif /* HAVE_ASCON */
    return EXPECT_RESULT();
} /* END test_ascon_aead128_edge_cases */
