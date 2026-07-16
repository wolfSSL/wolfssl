/* test_kdf.c
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
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>
#if defined(WC_SRTP_KDF) || defined(HAVE_CMAC_KDF)
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifdef HAVE_CMAC_KDF
    #include <wolfssl/wolfcrypt/cmac.h>
#endif
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_kdf.h>

/* ------------------------------------------------------------------ */
/* WOLF_CRYPTO_CB support for wc_KDA_KDF_twostep_cmac's dispatch guard */
/* ------------------------------------------------------------------ */
#if defined(HAVE_CMAC_KDF) && defined(WOLF_CRYPTO_CB)
#define TEST_KDF_CRYPTOCB_DEVID 0x4b444630 /* "KDF0" */

/* Toggled by the test below: when set, the callback fails outright instead
 * of computing the KDF, giving the (ret != CRYPTOCB_UNAVAILABLE) guard in
 * wc_KDA_KDF_twostep_cmac an independence pair (dispatch-taken-and-fails vs
 * dispatch-taken-and-succeeds), both within this one registered devId. */
static int test_kdf_cryptocb_force_fail = 0;

static int test_kdf_cryptocb(int cbDevId, wc_CryptoInfo* info, void* ctx)
{
    (void)ctx;
    if (cbDevId != TEST_KDF_CRYPTOCB_DEVID)
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    if (test_kdf_cryptocb_force_fail)
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    if (info->algo_type == WC_ALGO_TYPE_KDF &&
            info->kdf.type == WC_KDF_TYPE_TWOSTEP_CMAC) {
        /* Compute the real (software) answer via a devId-less call so we
         * do not recurse back into this same callback. */
        return wc_KDA_KDF_twostep_cmac(info->kdf.twostep_cmac.salt,
            info->kdf.twostep_cmac.saltSz, info->kdf.twostep_cmac.z,
            info->kdf.twostep_cmac.zSz, info->kdf.twostep_cmac.fixedInfo,
            info->kdf.twostep_cmac.fixedInfoSz, info->kdf.twostep_cmac.out,
            info->kdf.twostep_cmac.outSz, NULL, INVALID_DEVID);
    }
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}
#endif /* HAVE_CMAC_KDF && WOLF_CRYPTO_CB */

/*
 * MC/DC decision coverage: negative / argument-check / bad-selector /
 * short-buffer branches across kdf.c's public API (wc_PRF family, TLS 1.3
 * HKDF label expansion, SSH KDF, SRTP/SRTCP KDF, and the SP 800-56C /
 * SP 800-108 KDA KDFs). Each guarded sub-block auto-TEST_SKIPPED's when the
 * owning feature is compiled out.
 */
int test_wc_KdfDecisionCoverage(void)
{
    EXPECT_DECLS;
#ifndef NO_KDF

    /* ---------------------------------------------------------------- */
    /* wc_PRF(): switch(hash) default arm, and times==0 (resLen==0).     */
    /* ---------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_HMAC)
    {
        byte result[64] = {0};
        byte secret[16] = {0};
        byte seed[16] = {0};

        /* Unknown/unsupported mac id: falls through every enabled case to
         * the switch's default arm. */
        ExpectIntEQ(wc_PRF(result, 16, secret, sizeof(secret), seed,
            sizeof(seed), -1, HEAP_HINT, INVALID_DEVID),
            WC_NO_ERR_TRACE(HASH_TYPE_E));

#ifndef NO_SHA256
        /* resLen == 0: times computes to 0 (clang-static-analyzer-safe
         * guard), independent of which hash arm matched. */
        ExpectIntEQ(wc_PRF(result, 0, secret, sizeof(secret), seed,
            sizeof(seed), sha256_mac, HEAP_HINT, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    }
#endif /* WOLFSSL_HAVE_PRF && !NO_HMAC */

    /* ---------------------------------------------------------------- */
    /* wc_PRF_TLSv1(): the 3-operand OR buffer-size guard.                */
    /* ---------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_HMAC) && !defined(NO_OLD_TLS) && \
    !defined(NO_MD5) && !defined(NO_SHA)
    {
        /* MAX_PRF_HALF is 260 in the default configuration (no
         * HAVE_FFDHE_6144/8192). half = (secLen+1)/2, so secLen=521 gives
         * half=261 (>260). */
        static byte secretBig[600] = {0};
        static byte labelBuf[150] = {0};
        static byte seedBuf[150] = {0};
        static byte digestBuf[300] = {0};

        /* c0 = half > MAX_PRF_HALF: true, others held at trivial values. */
        ExpectIntEQ(wc_PRF_TLSv1(digestBuf, 16, secretBig, 521, labelBuf, 4,
            seedBuf, 4, HEAP_HINT, INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));

        /* c0 false (small secLen), c1 = labLen+seedLen > MAX_PRF_LABSEED
         * (128): true. */
        ExpectIntEQ(wc_PRF_TLSv1(digestBuf, 16, secretBig, 2, labelBuf, 70,
            seedBuf, 70, HEAP_HINT, INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));

        /* c0, c1 false; c2 = digLen > MAX_PRF_DIG (224): true. */
        ExpectIntEQ(wc_PRF_TLSv1(digestBuf, 225, secretBig, 2, labelBuf, 4,
            seedBuf, 4, HEAP_HINT, INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));

        /* Baseline: every leaf false, a real PRF computation. */
        ExpectIntEQ(wc_PRF_TLSv1(digestBuf, 16, secretBig, 4, labelBuf, 4,
            seedBuf, 4, HEAP_HINT, INVALID_DEVID), 0);
    }
#endif /* WOLFSSL_HAVE_PRF && !NO_HMAC && !NO_OLD_TLS && !NO_MD5 && !NO_SHA */

    /* ---------------------------------------------------------------- */
    /* wc_PRF_TLS(): useAtLeastSha256 branch + its labLen/seedLen guard.  */
    /* ---------------------------------------------------------------- */
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_HMAC)
    {
        static byte secretBuf[16] = {0};
        static byte labelBuf[150] = {0};
        static byte seedBuf[150] = {0};
        static byte digestBuf[64] = {0};

        /* useAtLeastSha256 true, labLen+seedLen > MAX_PRF_LABSEED (128). */
        ExpectIntEQ(wc_PRF_TLS(digestBuf, 16, secretBuf, sizeof(secretBuf),
            labelBuf, 70, seedBuf, 70, 1, sha256_mac, HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));

        /* useAtLeastSha256 false: BAD_FUNC_ARG when TLSv1 is compiled out,
         * else falls through to wc_PRF_TLSv1() successfully. */
#ifdef NO_OLD_TLS
        ExpectIntEQ(wc_PRF_TLS(digestBuf, 16, secretBuf, sizeof(secretBuf),
            labelBuf, 4, seedBuf, 4, 0, sha_mac, HEAP_HINT, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#elif !defined(NO_MD5) && !defined(NO_SHA)
        ExpectIntEQ(wc_PRF_TLS(digestBuf, 16, secretBuf, sizeof(secretBuf),
            labelBuf, 4, seedBuf, 4, 0, sha_mac, HEAP_HINT, INVALID_DEVID),
            0);
#endif
    }
#endif /* WOLFSSL_HAVE_PRF && !NO_HMAC */

    /* ---------------------------------------------------------------- */
    /* wc_Tls13_HKDF_Extract_ex(): switch(digest) default arm.           */
    /* ---------------------------------------------------------------- */
#if defined(HAVE_HKDF) && !defined(NO_HMAC)
    {
        byte prk[WC_MAX_DIGEST_SIZE] = {0};
        byte salt[8] = {0};
        byte ikm[WC_MAX_DIGEST_SIZE] = {0};

        /* WC_MD5 is not one of the switch's supported digest arms
         * (SHA256/SHA384/SHA512/SM3 only). */
        ExpectIntEQ(wc_Tls13_HKDF_Extract_ex(prk, salt, sizeof(salt), ikm, 4,
            WC_MD5, HEAP_HINT, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif /* HAVE_HKDF && !NO_HMAC */

    /* ---------------------------------------------------------------- */
    /* wc_Tls13_HKDF_Expand_Label_ex(): label-buffer size guard.          */
    /* ---------------------------------------------------------------- */
#if defined(HAVE_HKDF) && !defined(NO_HMAC) && !defined(NO_SHA256)
    {
        byte okm[64] = {0};
        byte prk[WC_SHA256_DIGEST_SIZE] = {0};
        static byte big[64] = {0};

        /* idx = 4 + protocolLen + labelLen + infoLen > MAX_TLS13_HKDF_LABEL_SZ
         * (47 + WC_MAX_DIGEST_SIZE). Using 3*50 = 150 bytes of payload is
         * larger than any realistic WC_MAX_DIGEST_SIZE bound. */
        ExpectIntEQ(wc_Tls13_HKDF_Expand_Label_ex(okm, sizeof(okm), prk,
            sizeof(prk), big, 50, big, 50, big, 50, WC_SHA256, HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BUFFER_E));
    }
#endif /* HAVE_HKDF && !NO_HMAC && !NO_SHA256 */

    /* ---------------------------------------------------------------- */
    /* wc_SSH_KDF(): NULL/zero-length arg checks (one leaf at a time),   */
    /* wc_HmacSizeByType() rejection, and _HashInit()'s switch default.  */
    /* ---------------------------------------------------------------- */
#if defined(WOLFSSL_WOLFSSH) && !defined(NO_SHA)
    {
        byte key[64] = {0};
        byte k[8] = {0x01};
        byte h[8] = {0x02};
        byte sessionId[8] = {0x03};

        /* Each leaf of the 8-operand OR shown true, in isolation, against
         * an otherwise-valid call. */
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'A', NULL, sizeof(key), k, sizeof(k),
            h, sizeof(h), sessionId, sizeof(sessionId)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'A', key, 0, k, sizeof(k), h,
            sizeof(h), sessionId, sizeof(sessionId)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'A', key, sizeof(key), NULL,
            sizeof(k), h, sizeof(h), sessionId, sizeof(sessionId)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'A', key, sizeof(key), k, 0, h,
            sizeof(h), sessionId, sizeof(sessionId)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'A', key, sizeof(key), k, sizeof(k),
            NULL, sizeof(h), sessionId, sizeof(sessionId)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'A', key, sizeof(key), k, sizeof(k),
            h, 0, sessionId, sizeof(sessionId)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'A', key, sizeof(key), k, sizeof(k),
            h, sizeof(h), NULL, sizeof(sessionId)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'A', key, sizeof(key), k, sizeof(k),
            h, sizeof(h), sessionId, 0),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* wc_HmacSizeByType() itself rejects the hashId (ret <= 0),
         * independent of _HashInit()'s own switch below. */
        ExpectIntEQ(wc_SSH_KDF(0xFF, 'A', key, sizeof(key), k, sizeof(k), h,
            sizeof(h), sessionId, sizeof(sessionId)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef WOLFSSL_SHA3
        /* wc_HmacSizeByType() accepts WC_SHA3_256, but the SSH KDF's own
         * hash union / _HashInit() switch does not implement SHA3: falls
         * through to _HashInit()'s default arm. */
        ExpectIntEQ(wc_SSH_KDF(WC_SHA3_256, 'A', key, sizeof(key), k,
            sizeof(k), h, sizeof(h), sessionId, sizeof(sessionId)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    }
#endif /* WOLFSSL_WOLFSSH && !NO_SHA */

    /* ---------------------------------------------------------------- */
    /* wc_SRTP_KDF(): the compound argument-validation OR (last leaf is  */
    /* itself an AND: (kdrIdx >= 0) && (idx == NULL)).                   */
    /* ---------------------------------------------------------------- */
#ifdef WC_SRTP_KDF
    {
        byte key[AES_128_KEY_SIZE] = {0};
        byte salt[WC_SRTP_MAX_SALT] = {0};
        byte idx[WC_SRTP_INDEX_LEN] = {0};
        byte key1[16] = {0};
        byte key2[16] = {0};
        byte key3[14] = {0};

        /* c0 = key == NULL: true. */
        ExpectIntEQ(wc_SRTP_KDF(NULL, sizeof(key), salt, sizeof(salt), -1,
            NULL, key1, sizeof(key1), key2, sizeof(key2), key3, sizeof(key3)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* c1 = keySz > AES_256_KEY_SIZE: true. */
        ExpectIntEQ(wc_SRTP_KDF(key, AES_256_KEY_SIZE + 1, salt,
            sizeof(salt), -1, NULL, key1, sizeof(key1), key2, sizeof(key2),
            key3, sizeof(key3)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* c2 = salt == NULL: true. */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), NULL, sizeof(salt), -1,
            NULL, key1, sizeof(key1), key2, sizeof(key2), key3, sizeof(key3)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* c3 = saltSz > WC_SRTP_MAX_SALT: true. */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt,
            WC_SRTP_MAX_SALT + 1, -1, NULL, key1, sizeof(key1), key2,
            sizeof(key2), key3, sizeof(key3)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* c4 = kdrIdx < -1: true. */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), -2,
            NULL, key1, sizeof(key1), key2, sizeof(key2), key3, sizeof(key3)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* c5 = kdrIdx > 24: true. */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), 25,
            idx, key1, sizeof(key1), key2, sizeof(key2), key3, sizeof(key3)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* c6a = kdrIdx >= 0: true; c6b = idx == NULL: true -> AND true. */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), 0,
            NULL, key1, sizeof(key1), key2, sizeof(key2), key3, sizeof(key3)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* c6a true, c6b false (idx supplied): AND false; every other leaf
         * false too -> success. */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), 0,
            idx, key1, sizeof(key1), key2, sizeof(key2), key3, sizeof(key3)),
            0);

        /* c6a false (kdrIdx == -1) masks c6b regardless of idx: success. */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), -1,
            NULL, key1, sizeof(key1), key2, sizeof(key2), key3, sizeof(key3)),
            0);

        /* key1/key2/key3 independently NULL-skippable. */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), -1,
            NULL, NULL, 0, key2, sizeof(key2), key3, sizeof(key3)), 0);
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), -1,
            NULL, key1, sizeof(key1), NULL, 0, key3, sizeof(key3)), 0);
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), -1,
            NULL, key1, sizeof(key1), key2, sizeof(key2), NULL, 0), 0);
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), -1,
            NULL, NULL, 0, NULL, 0, NULL, 0), 0);
    }

    /* wc_SRTCP_KDF_ex(): idxLenIndicator's own 3-way switch (its own
     * decision, independent of wc_SRTP_KDF's identical arg-validation
     * pattern above). */
    {
        byte key[AES_128_KEY_SIZE] = {0};
        byte salt[WC_SRTP_MAX_SALT] = {0};
        byte key1[16] = {0};

        ExpectIntEQ(wc_SRTCP_KDF_ex(key, sizeof(key), salt, sizeof(salt), -1,
            NULL, key1, sizeof(key1), NULL, 0, NULL, 0, 2 /* invalid */),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTCP_KDF_ex(key, sizeof(key), salt, sizeof(salt), -1,
            NULL, key1, sizeof(key1), NULL, 0, NULL, 0, WC_SRTCP_32BIT_IDX),
            0);
        ExpectIntEQ(wc_SRTCP_KDF_ex(key, sizeof(key), salt, sizeof(salt), -1,
            NULL, key1, sizeof(key1), NULL, 0, NULL, 0, WC_SRTCP_48BIT_IDX),
            0);

        /* One representative negative leaf in THIS function's own copy of
         * the arg-validation decision (key == NULL). */
        ExpectIntEQ(wc_SRTCP_KDF_ex(NULL, sizeof(key), salt, sizeof(salt),
            -1, NULL, key1, sizeof(key1), NULL, 0, NULL, 0,
            WC_SRTCP_32BIT_IDX), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

    /* wc_SRTP_KDF_label() / wc_SRTCP_KDF_label(): same pattern plus an
     * outKey == NULL leaf, each in its own function body. */
    {
        byte key[AES_128_KEY_SIZE] = {0};
        byte salt[WC_SRTP_MAX_SALT] = {0};
        byte outKey[16] = {0};

        ExpectIntEQ(wc_SRTP_KDF_label(key, sizeof(key), salt, sizeof(salt),
            -1, NULL, WC_SRTP_LABEL_ENCRYPTION, NULL, sizeof(outKey)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTP_KDF_label(key, sizeof(key), salt, sizeof(salt),
            -1, NULL, WC_SRTP_LABEL_ENCRYPTION, outKey, sizeof(outKey)), 0);
        ExpectIntEQ(wc_SRTP_KDF_label(NULL, sizeof(key), salt, sizeof(salt),
            -1, NULL, WC_SRTP_LABEL_ENCRYPTION, outKey, sizeof(outKey)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_SRTCP_KDF_label(key, sizeof(key), salt, sizeof(salt),
            -1, NULL, WC_SRTCP_LABEL_ENCRYPTION, NULL, sizeof(outKey)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTCP_KDF_label(key, sizeof(key), salt, sizeof(salt),
            -1, NULL, WC_SRTCP_LABEL_ENCRYPTION, outKey, sizeof(outKey)), 0);
        ExpectIntEQ(wc_SRTCP_KDF_label(NULL, sizeof(key), salt, sizeof(salt),
            -1, NULL, WC_SRTCP_LABEL_ENCRYPTION, outKey, sizeof(outKey)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Each remaining leaf of wc_SRTP_KDF_label()'s own copy of the
         * compound arg-validation OR, shown true in isolation. */
        ExpectIntEQ(wc_SRTP_KDF_label(key, AES_256_KEY_SIZE + 1, salt,
            sizeof(salt), -1, NULL, WC_SRTP_LABEL_ENCRYPTION, outKey,
            sizeof(outKey)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTP_KDF_label(key, sizeof(key), NULL, sizeof(salt),
            -1, NULL, WC_SRTP_LABEL_ENCRYPTION, outKey, sizeof(outKey)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTP_KDF_label(key, sizeof(key), salt,
            WC_SRTP_MAX_SALT + 1, -1, NULL, WC_SRTP_LABEL_ENCRYPTION, outKey,
            sizeof(outKey)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTP_KDF_label(key, sizeof(key), salt, sizeof(salt),
            -2, NULL, WC_SRTP_LABEL_ENCRYPTION, outKey, sizeof(outKey)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTP_KDF_label(key, sizeof(key), salt, sizeof(salt),
            25, NULL, WC_SRTP_LABEL_ENCRYPTION, outKey, sizeof(outKey)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Same 5 leaves for wc_SRTCP_KDF_label()'s own copy of the same
         * decision (a distinct source location from the above). */
        ExpectIntEQ(wc_SRTCP_KDF_label(key, AES_256_KEY_SIZE + 1, salt,
            sizeof(salt), -1, NULL, WC_SRTCP_LABEL_ENCRYPTION, outKey,
            sizeof(outKey)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTCP_KDF_label(key, sizeof(key), NULL, sizeof(salt),
            -1, NULL, WC_SRTCP_LABEL_ENCRYPTION, outKey, sizeof(outKey)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTCP_KDF_label(key, sizeof(key), salt,
            WC_SRTP_MAX_SALT + 1, -1, NULL, WC_SRTCP_LABEL_ENCRYPTION, outKey,
            sizeof(outKey)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTCP_KDF_label(key, sizeof(key), salt, sizeof(salt),
            -2, NULL, WC_SRTCP_LABEL_ENCRYPTION, outKey, sizeof(outKey)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SRTCP_KDF_label(key, sizeof(key), salt, sizeof(salt),
            25, NULL, WC_SRTCP_LABEL_ENCRYPTION, outKey, sizeof(outKey)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }

    /* wc_SRTP_KDF_kdr_to_idx(): while(kdr != 0) loop, false-immediately vs
     * true-at-least-once-then-false. */
    {
        ExpectIntEQ(wc_SRTP_KDF_kdr_to_idx(0), -1);
        ExpectIntEQ(wc_SRTP_KDF_kdr_to_idx(1), 0);
        ExpectIntEQ(wc_SRTP_KDF_kdr_to_idx(4), 2);
    }
#endif /* WC_SRTP_KDF */

    /* ---------------------------------------------------------------- */
    /* wc_KDA_KDF_onestep(): arg checks + hashType rejection + the       */
    /* while/if-tail loop decisions.                                    */
    /* ---------------------------------------------------------------- */
#if defined(WC_KDF_NIST_SP_800_56C) && !defined(NO_SHA256)
    {
        byte z[16] = {0};
        byte fixedInfo[8] = {0};
        byte output[128] = {0};

        /* output == NULL. */
        ExpectIntEQ(wc_KDA_KDF_onestep(z, sizeof(z), fixedInfo,
            sizeof(fixedInfo), 16, WC_SHA256, NULL, 16),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* outputSz < derivedSecretSz. */
        ExpectIntEQ(wc_KDA_KDF_onestep(z, sizeof(z), fixedInfo,
            sizeof(fixedInfo), 16, WC_SHA256, output, 8),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* z == NULL. */
        ExpectIntEQ(wc_KDA_KDF_onestep(NULL, sizeof(z), fixedInfo,
            sizeof(fixedInfo), 16, WC_SHA256, output, sizeof(output)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* zSz == 0. */
        ExpectIntEQ(wc_KDA_KDF_onestep(z, 0, fixedInfo, sizeof(fixedInfo),
            16, WC_SHA256, output, sizeof(output)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* fixedInfoSz > 0 && fixedInfo == NULL. */
        ExpectIntEQ(wc_KDA_KDF_onestep(z, sizeof(z), NULL, 4, 16, WC_SHA256,
            output, sizeof(output)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* derivedSecretSz == 0. */
        ExpectIntEQ(wc_KDA_KDF_onestep(z, sizeof(z), fixedInfo,
            sizeof(fixedInfo), 0, WC_SHA256, output, sizeof(output)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Bad hashType: wc_HashGetDigestSize() returns <= 0. */
        ExpectIntEQ(wc_KDA_KDF_onestep(z, sizeof(z), fixedInfo,
            sizeof(fixedInfo), 16, WC_HASH_TYPE_NONE, output,
            sizeof(output)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Baseline: exact multiple of the digest size (loop runs once,
         * outIdx reaches derivedSecretSz exactly, tail if-branch false). */
        ExpectIntEQ(wc_KDA_KDF_onestep(z, sizeof(z), fixedInfo,
            sizeof(fixedInfo), WC_SHA256_DIGEST_SIZE, WC_SHA256, output,
            sizeof(output)), 0);

        /* Not a multiple: loop runs once then the remainder tail runs
         * (outIdx < derivedSecretSz -> true). */
        ExpectIntEQ(wc_KDA_KDF_onestep(z, sizeof(z), fixedInfo,
            sizeof(fixedInfo), WC_SHA256_DIGEST_SIZE + 5, WC_SHA256, output,
            sizeof(output)), 0);

        /* Two full blocks exactly: loop iterates twice (while-condition
         * true then false), tail if-branch false again. */
        ExpectIntEQ(wc_KDA_KDF_onestep(z, sizeof(z), fixedInfo,
            sizeof(fixedInfo), 2 * WC_SHA256_DIGEST_SIZE, WC_SHA256, output,
            sizeof(output)), 0);
    }
#endif /* WC_KDF_NIST_SP_800_56C && !NO_SHA256 */

    /* ---------------------------------------------------------------- */
    /* wc_KDA_KDF_PRF_cmac() / wc_KDA_KDF_twostep_cmac(): arg checks +   */
    /* the while(len_rem >= BLOCK)/tail-if loop decisions.               */
    /* ---------------------------------------------------------------- */
#if defined(HAVE_CMAC_KDF) && defined(WOLFSSL_AES_128)
    {
        byte kin[AES_128_KEY_SIZE] = {0};
        byte fixedInfo[8] = {0};
        byte kout[64] = {0};

        /* Kin == NULL. */
        ExpectIntEQ(wc_KDA_KDF_PRF_cmac(NULL, sizeof(kin), fixedInfo,
            sizeof(fixedInfo), kout, 16, WC_CMAC_AES, HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Kout == NULL. */
        ExpectIntEQ(wc_KDA_KDF_PRF_cmac(kin, sizeof(kin), fixedInfo,
            sizeof(fixedInfo), NULL, 16, WC_CMAC_AES, HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* fixedInfoSz > 0 && fixedInfo == NULL. */
        ExpectIntEQ(wc_KDA_KDF_PRF_cmac(kin, sizeof(kin), NULL, 4, kout, 16,
            WC_CMAC_AES, HEAP_HINT, INVALID_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* KoutSz == 0. */
        ExpectIntEQ(wc_KDA_KDF_PRF_cmac(kin, sizeof(kin), fixedInfo,
            sizeof(fixedInfo), kout, 0, WC_CMAC_AES, HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* type != WC_CMAC_AES (only supported PRF type). */
        ExpectIntEQ(wc_KDA_KDF_PRF_cmac(kin, sizeof(kin), fixedInfo,
            sizeof(fixedInfo), kout, 16, (CmacType)0, HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* KoutSz < WC_AES_BLOCK_SIZE: main loop body never runs, tail
         * if(len_rem) true. */
        ExpectIntEQ(wc_KDA_KDF_PRF_cmac(kin, sizeof(kin), fixedInfo,
            sizeof(fixedInfo), kout, 8, WC_CMAC_AES, HEAP_HINT,
            INVALID_DEVID), 0);

        /* KoutSz not a multiple of WC_AES_BLOCK_SIZE: loop runs once, tail
         * if(len_rem) true. */
        ExpectIntEQ(wc_KDA_KDF_PRF_cmac(kin, sizeof(kin), fixedInfo,
            sizeof(fixedInfo), kout, 20, WC_CMAC_AES, HEAP_HINT,
            INVALID_DEVID), 0);

        /* KoutSz exact multiple: loop runs twice, tail if(len_rem) false. */
        ExpectIntEQ(wc_KDA_KDF_PRF_cmac(kin, sizeof(kin), fixedInfo,
            sizeof(fixedInfo), kout, 32, WC_CMAC_AES, HEAP_HINT,
            INVALID_DEVID), 0);

        /* Loop body's own "ret == 0 && fixedInfoSz > 0" guard: fixedInfoSz
         * operand false (fixedInfoSz == 0), ret == 0 held true, with a
         * KoutSz spanning one full block so the loop body actually runs. */
        ExpectIntEQ(wc_KDA_KDF_PRF_cmac(kin, sizeof(kin), NULL, 0, kout, 16,
            WC_CMAC_AES, HEAP_HINT, INVALID_DEVID), 0);

        /* Same guard's ret == 0 operand false: an invalid Kin length (not
         * 16/24/32) makes wc_InitCmac_ex() fail on the first loop
         * iteration, forcing ret != 0 by the time this guard is reached
         * (fixedInfoSz > 0 held true, as in the baseline calls above). */
        {
            byte kinBad[AES_128_KEY_SIZE + 4] = {0};
            ExpectIntEQ(wc_KDA_KDF_PRF_cmac(kinBad, sizeof(kinBad), fixedInfo,
                sizeof(fixedInfo), kout, 16, WC_CMAC_AES, HEAP_HINT,
                INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        }
    }

    {
        byte salt[AES_128_KEY_SIZE] = {0};
        byte z[16] = {0};
        byte fixedInfo[8] = {0};
        byte output[32] = {0};

        /* Bad salt_len: switch default arm. */
        ExpectIntEQ(wc_KDA_KDF_twostep_cmac(salt, 15, z, sizeof(z),
            fixedInfo, sizeof(fixedInfo), output, sizeof(output), HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* zSz == 0. */
        ExpectIntEQ(wc_KDA_KDF_twostep_cmac(salt, sizeof(salt), z, 0,
            fixedInfo, sizeof(fixedInfo), output, sizeof(output), HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* outputSz == 0. */
        ExpectIntEQ(wc_KDA_KDF_twostep_cmac(salt, sizeof(salt), z,
            sizeof(z), fixedInfo, sizeof(fixedInfo), output, 0, HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* fixedInfoSz > 0 && fixedInfo == NULL. */
        ExpectIntEQ(wc_KDA_KDF_twostep_cmac(salt, sizeof(salt), z,
            sizeof(z), NULL, 4, output, sizeof(output), HEAP_HINT,
            INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* salt == NULL. */
        ExpectIntEQ(wc_KDA_KDF_twostep_cmac(NULL, sizeof(salt), z,
            sizeof(z), fixedInfo, sizeof(fixedInfo), output, sizeof(output),
            HEAP_HINT, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* z == NULL. */
        ExpectIntEQ(wc_KDA_KDF_twostep_cmac(salt, sizeof(salt), NULL,
            sizeof(z), fixedInfo, sizeof(fixedInfo), output, sizeof(output),
            HEAP_HINT, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* output == NULL. */
        ExpectIntEQ(wc_KDA_KDF_twostep_cmac(salt, sizeof(salt), z,
            sizeof(z), fixedInfo, sizeof(fixedInfo), NULL, sizeof(output),
            HEAP_HINT, INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* Baseline: valid two-step derivation, dispatch not taken
         * (devId == INVALID_DEVID). */
        ExpectIntEQ(wc_KDA_KDF_twostep_cmac(salt, sizeof(salt), z,
            sizeof(z), fixedInfo, sizeof(fixedInfo), output, sizeof(output),
            HEAP_HINT, INVALID_DEVID), 0);

#if defined(WOLF_CRYPTO_CB)
        /* devId != INVALID_DEVID: dispatch taken. Independence pair for
         * the (ret != CRYPTOCB_UNAVAILABLE) guard: succeeds, then fails
         * outright, both via the SAME registered devId. */
        ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_KDF_CRYPTOCB_DEVID,
            test_kdf_cryptocb, NULL), 0);

        test_kdf_cryptocb_force_fail = 0;
        ExpectIntEQ(wc_KDA_KDF_twostep_cmac(salt, sizeof(salt), z,
            sizeof(z), fixedInfo, sizeof(fixedInfo), output, sizeof(output),
            HEAP_HINT, TEST_KDF_CRYPTOCB_DEVID), 0);

        test_kdf_cryptocb_force_fail = 1;
        ExpectIntEQ(wc_KDA_KDF_twostep_cmac(salt, sizeof(salt), z,
            sizeof(z), fixedInfo, sizeof(fixedInfo), output, sizeof(output),
            HEAP_HINT, TEST_KDF_CRYPTOCB_DEVID),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        test_kdf_cryptocb_force_fail = 0;

        wc_CryptoCb_UnRegisterDevice(TEST_KDF_CRYPTOCB_DEVID);
#endif /* WOLF_CRYPTO_CB */
    }
#endif /* HAVE_CMAC_KDF && WOLFSSL_AES_128 */

#endif /* !NO_KDF */
    return EXPECT_RESULT();
} /* END test_wc_KdfDecisionCoverage */

/*
 * MC/DC feature coverage: positive multi-hash / multi-chunk paths driving
 * true-side loop and switch-arm coverage for kdf.c's public API.
 */
int test_wc_KdfFeatureCoverage(void)
{
    EXPECT_DECLS;
#ifndef NO_KDF

    /* wc_PRF() across every enabled hash arm, and both the
     * exact-multiple-of-digest-length and partial-last-block sides of
     * "(i != lastTime) || !lastLen". */
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_HMAC)
    {
        byte secret[32] = {0};
        byte seed[16] = {0};
        byte result[256] = {0};

#ifndef NO_MD5
        ExpectIntEQ(wc_PRF(result, WC_MD5_DIGEST_SIZE, secret,
            sizeof(secret), seed, sizeof(seed), md5_mac, HEAP_HINT,
            INVALID_DEVID), 0);
#endif
#ifndef NO_SHA
        ExpectIntEQ(wc_PRF(result, WC_SHA_DIGEST_SIZE - 4, secret,
            sizeof(secret), seed, sizeof(seed), sha_mac, HEAP_HINT,
            INVALID_DEVID), 0);
#endif
#ifndef NO_SHA256
        /* Exact multiple over two blocks: lastLen == 0 on the final
         * iteration. */
        ExpectIntEQ(wc_PRF(result, 2 * WC_SHA256_DIGEST_SIZE, secret,
            sizeof(secret), seed, sizeof(seed), sha256_mac, HEAP_HINT,
            INVALID_DEVID), 0);
        /* Multi-block with a partial tail: lastLen != 0 on the final
         * iteration. */
        ExpectIntEQ(wc_PRF(result, 2 * WC_SHA256_DIGEST_SIZE + 4, secret,
            sizeof(secret), seed, sizeof(seed), sha256_mac, HEAP_HINT,
            INVALID_DEVID), 0);
#endif
#ifdef WOLFSSL_SHA384
        ExpectIntEQ(wc_PRF(result, WC_SHA384_DIGEST_SIZE, secret,
            sizeof(secret), seed, sizeof(seed), sha384_mac, HEAP_HINT,
            INVALID_DEVID), 0);
#endif
#ifdef WOLFSSL_SHA512
        ExpectIntEQ(wc_PRF(result, WC_SHA512_DIGEST_SIZE, secret,
            sizeof(secret), seed, sizeof(seed), sha512_mac, HEAP_HINT,
            INVALID_DEVID), 0);
#endif
    }
#endif /* WOLFSSL_HAVE_PRF && !NO_HMAC */

    /* wc_PRF_TLS(): drive the hash_type override guard's 3 MC/DC leaves
     * (TF/FT/FF) plus both sides of useAtLeastSha256. */
#if defined(WOLFSSL_HAVE_PRF) && !defined(NO_HMAC) && !defined(NO_SHA256)
    {
        byte secret[16] = {0};
        byte label[8] = {0};
        byte seed[8] = {0};
        byte digest[64] = {0};

#ifndef NO_SHA
        /* c0 (hash_type < sha256_mac) true: forced up to sha256_mac. */
        ExpectIntEQ(wc_PRF_TLS(digest, WC_SHA256_DIGEST_SIZE, secret,
            sizeof(secret), label, sizeof(label), seed, sizeof(seed), 1,
            sha_mac, HEAP_HINT, INVALID_DEVID), 0);
#endif
        /* c0 false, c1 (hash_type == blake2b_mac) true: forced up. */
        ExpectIntEQ(wc_PRF_TLS(digest, WC_SHA256_DIGEST_SIZE, secret,
            sizeof(secret), label, sizeof(label), seed, sizeof(seed), 1,
            blake2b_mac, HEAP_HINT, INVALID_DEVID), 0);
        /* c0, c1 both false: hash_type left as-is (already sha256_mac). */
        ExpectIntEQ(wc_PRF_TLS(digest, WC_SHA256_DIGEST_SIZE, secret,
            sizeof(secret), label, sizeof(label), seed, sizeof(seed), 1,
            sha256_mac, HEAP_HINT, INVALID_DEVID), 0);
#ifdef WOLFSSL_SHA384
        /* c0, c1 both false with a hash_type genuinely above sha256_mac:
         * no override, sha384_mac used directly. */
        ExpectIntEQ(wc_PRF_TLS(digest, WC_SHA384_DIGEST_SIZE, secret,
            sizeof(secret), label, sizeof(label), seed, sizeof(seed), 1,
            sha384_mac, HEAP_HINT, INVALID_DEVID), 0);
#endif

#if !defined(NO_OLD_TLS) && !defined(NO_MD5) && !defined(NO_SHA)
        /* useAtLeastSha256 == 0: routed to wc_PRF_TLSv1(). */
        ExpectIntEQ(wc_PRF_TLS(digest, 16, secret, sizeof(secret), label,
            sizeof(label), seed, sizeof(seed), 0, sha_mac, HEAP_HINT,
            INVALID_DEVID), 0);
#endif
    }
#endif /* WOLFSSL_HAVE_PRF && !NO_HMAC && !NO_SHA256 */

    /* wc_Tls13_HKDF_Extract()/_ex(): ikmLen == 0 zero-fill branch vs a
     * caller-supplied IKM, across each supported digest, plus the thin
     * non-_ex wrapper. */
#if defined(HAVE_HKDF) && !defined(NO_HMAC)
    {
        byte prk[WC_MAX_DIGEST_SIZE] = {0};
        byte salt[8] = {0};
        byte ikm[WC_MAX_DIGEST_SIZE] = {0};

#ifndef NO_SHA256
        /* ikmLen == 0: internal zero-fill branch. */
        ExpectIntEQ(wc_Tls13_HKDF_Extract_ex(prk, salt, sizeof(salt), ikm, 0,
            WC_SHA256, HEAP_HINT, INVALID_DEVID), 0);
        /* ikmLen != 0: caller-supplied IKM used as-is. */
        ikm[0] = 0x11;
        ExpectIntEQ(wc_Tls13_HKDF_Extract_ex(prk, salt, sizeof(salt), ikm,
            WC_SHA256_DIGEST_SIZE, WC_SHA256, HEAP_HINT, INVALID_DEVID), 0);
        /* Thin (non-_ex) wrapper. */
        ExpectIntEQ(wc_Tls13_HKDF_Extract(prk, salt, sizeof(salt), ikm,
            WC_SHA256_DIGEST_SIZE, WC_SHA256), 0);
#endif
#ifdef WOLFSSL_SHA384
        ExpectIntEQ(wc_Tls13_HKDF_Extract_ex(prk, salt, sizeof(salt), ikm, 0,
            WC_SHA384, HEAP_HINT, INVALID_DEVID), 0);
#endif
#if defined(WOLFSSL_TLS13_SHA512) && defined(WOLFSSL_SHA512)
        ExpectIntEQ(wc_Tls13_HKDF_Extract_ex(prk, salt, sizeof(salt), ikm, 0,
            WC_SHA512, HEAP_HINT, INVALID_DEVID), 0);
#endif
    }
#endif /* HAVE_HKDF && !NO_HMAC */

    /* wc_Tls13_HKDF_Expand_Label()/_ex(): protocolLen/labelLen/infoLen
     * each independently zero vs non-zero, across each supported digest,
     * plus the thin non-_ex wrapper. */
#if defined(HAVE_HKDF) && !defined(NO_HMAC) && !defined(NO_SHA256)
    {
        byte okm[32] = {0};
        byte prk[WC_SHA256_DIGEST_SIZE] = {0};
        byte protocol[8] = { 't','l','s','1','3',' ',0,0 };
        byte label[8] = { 'l','a','b','e','l',0,0,0 };
        byte info[8] = {0};

        /* All three zero. */
        ExpectIntEQ(wc_Tls13_HKDF_Expand_Label_ex(okm, sizeof(okm), prk,
            sizeof(prk), protocol, 0, label, 0, info, 0, WC_SHA256,
            HEAP_HINT, INVALID_DEVID), 0);
        /* All three non-zero. */
        ExpectIntEQ(wc_Tls13_HKDF_Expand_Label_ex(okm, sizeof(okm), prk,
            sizeof(prk), protocol, 6, label, 5, info, 4, WC_SHA256,
            HEAP_HINT, INVALID_DEVID), 0);
        /* Thin (non-_ex) wrapper. */
        ExpectIntEQ(wc_Tls13_HKDF_Expand_Label(okm, sizeof(okm), prk,
            sizeof(prk), protocol, 6, label, 5, info, 4, WC_SHA256), 0);

#ifdef WOLFSSL_SHA384
        ExpectIntEQ(wc_Tls13_HKDF_Expand_Label_ex(okm, sizeof(okm), prk,
            sizeof(prk), protocol, 6, label, 5, info, 4, WC_SHA384,
            HEAP_HINT, INVALID_DEVID), 0);
#endif
    }
#endif /* HAVE_HKDF && !NO_HMAC && !NO_SHA256 */

    /* wc_Tls13_HKDF_Expand_Label_Alloc(): only compiled with
     * WOLFSSL_TICKET_NONCE_MALLOC (its own dedicated variant). */
#if defined(HAVE_HKDF) && !defined(NO_HMAC) && !defined(NO_SHA256) && \
    defined(WOLFSSL_TICKET_NONCE_MALLOC) && \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && \
     FIPS_VERSION_GE(5,3)))
    {
        byte okm[32] = {0};
        byte prk[WC_SHA256_DIGEST_SIZE] = {0};
        byte protocol[6] = { 't','l','s','1','3',' ' };
        byte label[5] = { 'l','a','b','e','l' };
        byte info[4] = {0};

        ExpectIntEQ(wc_Tls13_HKDF_Expand_Label_Alloc(okm, sizeof(okm), prk,
            sizeof(prk), protocol, sizeof(protocol), label, sizeof(label),
            info, sizeof(info), WC_SHA256, HEAP_HINT), 0);
    }
#endif

    /* wc_SSH_KDF() across each supported hashId and several keyIds,
     * driving blocks==0 vs blocks>0, the tail remainder branch, and the
     * kPad (top-bit-of-k[0]) branch. */
#ifdef WOLFSSL_WOLFSSH
    {
        byte k[8] = {0x01};
        byte kPadded[8] = {0}; /* top bit set: exercises kPad path */
        byte h[8] = {0x02};
        byte sessionId[8] = {0x03};
        byte key[160] = {0};

        kPadded[0] = 0x80;

#ifndef NO_SHA
        /* digestSz(SHA1)=20: keySz=10 -> blocks==0, remainder>0. */
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'A', key, 10, k, sizeof(k), h,
            sizeof(h), sessionId, sizeof(sessionId)), 0);
        /* keySz==20 -> blocks==1 (loop body skipped), remainder==0. */
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'B', key, 20, k, sizeof(k), h,
            sizeof(h), sessionId, sizeof(sessionId)), 0);
        /* keySz==43 -> blocks==2 (loop runs once), remainder>0, with kPad
         * (k[0] top bit set) true. */
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'C', key, 43, kPadded, sizeof(kPadded),
            h, sizeof(h), sessionId, sizeof(sessionId)), 0);
        /* keySz==40 -> blocks==2, remainder==0. */
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'D', key, 40, k, sizeof(k), h,
            sizeof(h), sessionId, sizeof(sessionId)), 0);
        /* keySz==43 -> blocks==2 (loop runs once), remainder>0, with kPad
         * (k[0] top bit clear) false: independence pair for the
         * remainder-tail's "ret == 0 && kPad" guard's kPad operand,
         * against the 'C' case above (same ret == 0, kPad true). */
        ExpectIntEQ(wc_SSH_KDF(WC_SHA, 'E', key, 43, k, sizeof(k), h,
            sizeof(h), sessionId, sizeof(sessionId)), 0);
#endif
#ifndef NO_SHA256
        ExpectIntEQ(wc_SSH_KDF(WC_SHA256, 'A', key, 16, k, sizeof(k), h,
            sizeof(h), sessionId, sizeof(sessionId)), 0);
#endif
#ifdef WOLFSSL_SHA384
        ExpectIntEQ(wc_SSH_KDF(WC_SHA384, 'A', key, 16, k, sizeof(k), h,
            sizeof(h), sessionId, sizeof(sessionId)), 0);
#endif
#ifdef WOLFSSL_SHA512
        ExpectIntEQ(wc_SSH_KDF(WC_SHA512, 'A', key, 16, k, sizeof(k), h,
            sizeof(h), sessionId, sizeof(sessionId)), 0);
#endif
    }
#endif /* WOLFSSL_WOLFSSH */

    /* wc_SRTP_KDF()/wc_SRTCP_KDF() happy paths, including kdrIdx >= 0 with
     * a real index (bit-shift XOR branch) and kdrIdx == -1 (no XOR). */
#ifdef WC_SRTP_KDF
    {
        byte key[AES_128_KEY_SIZE] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
        byte salt[WC_SRTP_MAX_SALT] = {0};
        byte idx[WC_SRTP_INDEX_LEN] = { 0, 0, 0, 0, 0, 1 };
        byte key1[16] = {0};
        byte key2[20] = {0};
        byte key3[14] = {0};

        /* kdrIdx == -1: no XOR of idx (idx may be NULL). */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), -1,
            NULL, key1, sizeof(key1), key2, sizeof(key2), key3,
            sizeof(key3)), 0);
        /* kdrIdx a multiple of 8 (bits == 0): plain byte-aligned XOR. */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), 8, idx,
            key1, sizeof(key1), key2, sizeof(key2), key3, sizeof(key3)), 0);
        /* kdrIdx not a multiple of 8: bit-shifted XOR path. */
        ExpectIntEQ(wc_SRTP_KDF(key, sizeof(key), salt, sizeof(salt), 3, idx,
            key1, sizeof(key1), key2, sizeof(key2), key3, sizeof(key3)), 0);

        ExpectIntEQ(wc_SRTCP_KDF(key, sizeof(key), salt, sizeof(salt), -1,
            NULL, key1, sizeof(key1), key2, sizeof(key2), key3,
            sizeof(key3)), 0);
    }
#endif /* WC_SRTP_KDF */

#endif /* !NO_KDF */
    return EXPECT_RESULT();
} /* END test_wc_KdfFeatureCoverage */
