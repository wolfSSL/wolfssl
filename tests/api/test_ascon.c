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

    /* Negative test: corrupted tag must be rejected with ASCON_AUTH_E. */
    {
        byte key[ASCON_AEAD128_KEY_SZ];
        byte nonce[ASCON_AEAD128_NONCE_SZ];
        byte pt[4] = { 0x00, 0x01, 0x02, 0x03 };
        byte ct[4];
        byte tag[ASCON_AEAD128_TAG_SZ];
        byte buf[4];

        XMEMSET(key, 0xAA, sizeof(key));
        XMEMSET(nonce, 0xBB, sizeof(nonce));

        ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, NULL, 0), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, ct, pt,
                    sizeof(pt)), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(asconAEAD, tag), 0);

        /* Corrupt one byte of the tag. */
        tag[0] ^= 0x01;

        ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, NULL, 0), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, buf, ct,
                    sizeof(ct)), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, tag),
                    WC_NO_ERR_TRACE(ASCON_AUTH_E));
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

/*
 * Decision coverage for the argument- and state-validation guards in
 * wolfcrypt/src/ascon.c:
 *   - wc_AsconHash256_Update:       a == NULL || (data == NULL && dataSz != 0)
 *   - wc_AsconHash256_Final:        a == NULL || hash == NULL
 *   - wc_AsconAEAD128_SetKey:       a == NULL || key == NULL
 *   - wc_AsconAEAD128_SetNonce:     a == NULL || nonce == NULL
 *   - wc_AsconAEAD128_SetAD:        a == NULL || (ad == NULL && adSz > 0)
 *                                   !keySet || !nonceSet
 *   - wc_AsconAEAD128_EncryptUpdate: a == NULL || (in == NULL && inSz > 0)
 *                                   !keySet || !nonceSet || !adSet
 *   - wc_AsconAEAD128_EncryptFinal:  a == NULL || tag == NULL
 *                                   !keySet || !nonceSet || !adSet
 *   - wc_AsconAEAD128_DecryptUpdate: a == NULL || (in == NULL && inSz > 0)
 *                                   !keySet || !nonceSet || !adSet
 *   - wc_AsconAEAD128_DecryptFinal:  a == NULL || tag == NULL
 *                                   !keySet || !nonceSet || !adSet
 *
 * Every operand of every ||/&& above is driven independently true and
 * false so both halves of each short-circuit decision are exercised.
 */
int test_ascon_decision_coverage(void)
{
    EXPECT_DECLS;
#ifdef HAVE_ASCON
    wc_AsconHash256* asconHash = NULL;
    wc_AsconAEAD128* asconAEAD = NULL;
    byte data[8] = { 0 };
    byte hashOut[ASCON_HASH256_SZ] = { 0 };
    byte key[ASCON_AEAD128_KEY_SZ] = { 0 };
    byte nonce[ASCON_AEAD128_NONCE_SZ] = { 0 };
    byte ad[8] = { 0 };
    byte ptbuf[8] = { 0 };
    byte ctbuf[8] = { 0 };
    byte tag[ASCON_AEAD128_TAG_SZ] = { 0 };
    byte dummy[1] = { 0 }; /* non-NULL placeholder for 0-length in/ad args */

    /* ---------------------------------------------------------------- */
    /* wc_AsconHash256_Update:                                           */
    /*   if (a == NULL || (data == NULL && dataSz != 0))                 */
    /* ---------------------------------------------------------------- */
    ExpectNotNull(asconHash = wc_AsconHash256_New());

    /* a == NULL -> true, short-circuits, BAD_FUNC_ARG */
    ExpectIntEQ(wc_AsconHash256_Update(NULL, data, sizeof(data)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* a != NULL, data == NULL, dataSz != 0 -> inner && true, BAD_FUNC_ARG */
    ExpectIntEQ(wc_AsconHash256_Update(asconHash, NULL, sizeof(data)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* a != NULL, data == NULL, dataSz == 0 -> inner && false (dataSz
     * operand flips independently), overall false, proceeds */
    ExpectIntEQ(wc_AsconHash256_Update(asconHash, NULL, 0), 0);
    /* a != NULL, data != NULL -> both operands false, proceeds */
    ExpectIntEQ(wc_AsconHash256_Update(asconHash, data, sizeof(data)), 0);

    /* ---------------------------------------------------------------- */
    /* wc_AsconHash256_Final: if (a == NULL || hash == NULL)             */
    /* ---------------------------------------------------------------- */
    ExpectIntEQ(wc_AsconHash256_Final(NULL, hashOut),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AsconHash256_Final(asconHash, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AsconHash256_Final(asconHash, hashOut), 0);

    wc_AsconHash256_Free(asconHash);

    /* ---------------------------------------------------------------- */
    /* wc_AsconAEAD128_SetKey: if (a == NULL || key == NULL)             */
    /* ---------------------------------------------------------------- */
    ExpectNotNull(asconAEAD = wc_AsconAEAD128_New());

    ExpectIntEQ(wc_AsconAEAD128_SetKey(NULL, key),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);

    /* ---------------------------------------------------------------- */
    /* wc_AsconAEAD128_SetNonce: if (a == NULL || nonce == NULL)         */
    /* ---------------------------------------------------------------- */
    ExpectIntEQ(wc_AsconAEAD128_SetNonce(NULL, nonce),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);

    /* ---------------------------------------------------------------- */
    /* wc_AsconAEAD128_SetAD:                                            */
    /*   if (a == NULL || (ad == NULL && adSz > 0))                      */
    /*   if (!keySet || !nonceSet)                                       */
    /* At this point asconAEAD has keySet=1, nonceSet=1 (above), so the  */
    /* arg-validation cases below fall through to a fully-set state.    */
    /* ---------------------------------------------------------------- */
    ExpectIntEQ(wc_AsconAEAD128_SetAD(NULL, ad, sizeof(ad)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* a != NULL, ad == NULL, adSz > 0 -> inner && true, BAD_FUNC_ARG */
    ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, NULL, sizeof(ad)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* a != NULL, ad == NULL, adSz == 0 -> inner && false, proceeds past
     * arg check to the state check (both keySet/nonceSet true here) */
    ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, NULL, 0), 0);

    /* State guard on SetAD: !keySet || !nonceSet, using freshly Init'd
     * contexts to isolate each operand. */
    {
        wc_AsconAEAD128 stateCtx;

        /* Neither key nor nonce set -> !keySet true, short-circuits */
        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(&stateCtx, ad, sizeof(ad)),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        /* Only key set -> !keySet false, !nonceSet true */
        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(&stateCtx, ad, sizeof(ad)),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        /* Both key and nonce set -> both operands false, proceeds */
        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(&stateCtx, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(&stateCtx, ad, sizeof(ad)), 0);
        wc_AsconAEAD128_Clear(&stateCtx);
    }

    /* Finish setting up asconAEAD (key+nonce already set above) with AD
     * so it is fully configured for the Encrypt/Decrypt tests below. */
    ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, ad, sizeof(ad)), 0);

    /* ---------------------------------------------------------------- */
    /* wc_AsconAEAD128_EncryptUpdate:                                    */
    /*   if (a == NULL || (in == NULL && inSz > 0))                      */
    /*   if (!keySet || !nonceSet || !adSet)                             */
    /* asconAEAD is fully configured (keySet/nonceSet/adSet all true),   */
    /* so the arg-validation cases fall through to a real encrypt call.  */
    /* ---------------------------------------------------------------- */
    ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(NULL, ctbuf, ptbuf,
        sizeof(ptbuf)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* a != NULL, in == NULL, inSz > 0 -> inner && true, BAD_FUNC_ARG */
    ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, ctbuf, NULL,
        sizeof(ptbuf)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* a != NULL, in == NULL, inSz == 0 -> inner && false, proceeds */
    ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, ctbuf, NULL, 0), 0);
    /* both operands false -> proceeds, real encrypt */
    ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(asconAEAD, ctbuf, ptbuf,
        sizeof(ptbuf)), 0);

    /* State guard on EncryptUpdate: !keySet || !nonceSet || !adSet,
     * isolated with freshly Init'd contexts at each stage. */
    {
        wc_AsconAEAD128 stateCtx;

        /* Nothing set -> !keySet true, short-circuits */
        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(&stateCtx, ctbuf, ptbuf,
            sizeof(ptbuf)), WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        /* Only key set -> !keySet false, !nonceSet true */
        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(&stateCtx, ctbuf, ptbuf,
            sizeof(ptbuf)), WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        /* Key and nonce set, AD not set -> !keySet false, !nonceSet
         * false, !adSet true */
        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(&stateCtx, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(&stateCtx, ctbuf, ptbuf,
            sizeof(ptbuf)), WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        /* Key, nonce, and AD all set -> all three operands false */
        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(&stateCtx, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(&stateCtx, ad, sizeof(ad)), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptUpdate(&stateCtx, ctbuf, ptbuf,
            sizeof(ptbuf)), 0);
        wc_AsconAEAD128_Clear(&stateCtx);
    }

    /* ---------------------------------------------------------------- */
    /* wc_AsconAEAD128_EncryptFinal:                                     */
    /*   if (a == NULL || tag == NULL)                                   */
    /*   if (!keySet || !nonceSet || !adSet)                             */
    /* asconAEAD is fully configured and mid-encrypt from above, so the  */
    /* good call below completes the operation and clears the context.  */
    /* ---------------------------------------------------------------- */
    ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(NULL, tag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(asconAEAD, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(asconAEAD, tag), 0);

    /* State guard on EncryptFinal: !keySet || !nonceSet || !adSet. */
    {
        wc_AsconAEAD128 stateCtx;

        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(&stateCtx, tag),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(&stateCtx, tag),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(&stateCtx, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(&stateCtx, tag),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        /* Fully set, but op has never been set by EncryptUpdate -> passes
         * the keySet/nonceSet/adSet guard, still exercises operand
         * independence for adSet (false here vs true above). */
        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(&stateCtx, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(&stateCtx, ad, sizeof(ad)), 0);
        ExpectIntEQ(wc_AsconAEAD128_EncryptFinal(&stateCtx, tag),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);
    }

    /* ---------------------------------------------------------------- */
    /* wc_AsconAEAD128_DecryptUpdate:                                    */
    /*   if (a == NULL || (in == NULL && inSz > 0))                      */
    /*   if (!keySet || !nonceSet || !adSet)                             */
    /* Re-configure asconAEAD (Clear'd by the EncryptFinal above) fully   */
    /* so the arg-validation cases fall through to a real decrypt call.  */
    /* ---------------------------------------------------------------- */
    ExpectIntEQ(wc_AsconAEAD128_Init(asconAEAD), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetKey(asconAEAD, key), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetNonce(asconAEAD, nonce), 0);
    ExpectIntEQ(wc_AsconAEAD128_SetAD(asconAEAD, ad, sizeof(ad)), 0);

    ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(NULL, ptbuf, ctbuf,
        sizeof(ctbuf)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* a != NULL, in == NULL, inSz > 0 -> inner && true, BAD_FUNC_ARG */
    ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, ptbuf, NULL,
        sizeof(ctbuf)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* NOTE: unlike wc_AsconHash256_Update/wc_AsconAEAD128_SetAD (which
     * return early when the size is 0, before the pointer is ever
     * touched) and wc_AsconAEAD128_EncryptUpdate (whose only copy out of
     * the 0-length input reads from internal state, not from `in`),
     * wc_AsconAEAD128_DecryptUpdate falls through on inSz == 0 all the
     * way to "XMEMCPY(a->state.s64, in, inSz)" (ascon.c:489), which
     * passes `in` as the memcpy source unconditionally. Confirmed via
     * -fsanitize=undefined that DecryptUpdate(ctx, out, NULL, 0) raises
     * "null pointer passed as argument 2, which is declared to never be
     * null" even though the guard on line 452 explicitly allows this
     * call. Using a real NULL here would make this test UBSan-unsafe, so
     * a non-NULL 1-byte placeholder is used instead (same convention as
     * `dummy` in test_ascon_aead128_edge_cases above). This means the
     * independent effect of the inSz > 0 operand (holding in == NULL
     * fixed) cannot be safely demonstrated for DecryptUpdate; this is a
     * disclosed MC/DC residual tied to the underlying code fragility. */
    ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, ptbuf, dummy, 0), 0);
    /* both operands false -> proceeds, real decrypt */
    ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(asconAEAD, ptbuf, ctbuf,
        sizeof(ctbuf)), 0);

    /* State guard on DecryptUpdate: !keySet || !nonceSet || !adSet. */
    {
        wc_AsconAEAD128 stateCtx;

        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(&stateCtx, ptbuf, ctbuf,
            sizeof(ctbuf)), WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(&stateCtx, ptbuf, ctbuf,
            sizeof(ctbuf)), WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(&stateCtx, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(&stateCtx, ptbuf, ctbuf,
            sizeof(ctbuf)), WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(&stateCtx, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(&stateCtx, ad, sizeof(ad)), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptUpdate(&stateCtx, ptbuf, ctbuf,
            sizeof(ctbuf)), 0);
        wc_AsconAEAD128_Clear(&stateCtx);
    }

    /* ---------------------------------------------------------------- */
    /* wc_AsconAEAD128_DecryptFinal:                                     */
    /*   if (a == NULL || tag == NULL)                                   */
    /*   if (!keySet || !nonceSet || !adSet)                             */
    /* asconAEAD is fully configured and mid-decrypt from above.         */
    /* ---------------------------------------------------------------- */
    ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(NULL, tag),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* tag will not match (arbitrary all-zero buffer vs real ciphertext),
     * but that only affects the ConstantCompare below the guards -- the
     * decisions under test (arg/state guards) are still both exercised. */
    ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(asconAEAD, tag),
        WC_NO_ERR_TRACE(ASCON_AUTH_E));

    /* State guard on DecryptFinal: !keySet || !nonceSet || !adSet. */
    {
        wc_AsconAEAD128 stateCtx;

        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(&stateCtx, tag),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(&stateCtx, tag),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(&stateCtx, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(&stateCtx, tag),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);

        /* Fully set, op never set by DecryptUpdate -> passes the
         * keySet/nonceSet/adSet guard (all false), then falls through to
         * the op-mismatch check (BAD_STATE_E), which is outside the
         * scope of the decisions targeted here but is a valid, reachable
         * return path for this call sequence. */
        ExpectIntEQ(wc_AsconAEAD128_Init(&stateCtx), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetKey(&stateCtx, key), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetNonce(&stateCtx, nonce), 0);
        ExpectIntEQ(wc_AsconAEAD128_SetAD(&stateCtx, ad, sizeof(ad)), 0);
        ExpectIntEQ(wc_AsconAEAD128_DecryptFinal(&stateCtx, tag),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_AsconAEAD128_Clear(&stateCtx);
    }

    wc_AsconAEAD128_Free(asconAEAD);
#endif /* HAVE_ASCON */
    return EXPECT_RESULT();
} /* END test_ascon_decision_coverage */
