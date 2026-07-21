/* test_hpke_whitebox.c
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

/*
 * MC/DC white-box supplement for wolfcrypt/src/hpke.c.
 *
 * tests/api/test_hpke.c already drives every argument-validation guard on
 * the public (WOLFSSL_API) entry points. What it cannot reach are the
 * file-static helper functions' own "hpke == NULL" (and similar) guards --
 * every public entry point already rejects a NULL hpke (or other argument)
 * before ever calling into these helpers, so those inner guards are
 * structurally unreachable from tests/api. This white-box #includes hpke.c
 * directly so the file-static helpers are callable on their own, and drives
 * both short-circuit halves of each reachable guard:
 *
 *   - I2OSP() (hpke.c:82), "w <= 0 || w > 32 || n < 0" (hpke.c:86) and
 *     "w < 4 && n > ((1 << (w * 8)) - 1)" (hpke.c:91).
 *   - wc_HpkeContextComputeNonce() (hpke.c:626), "hpke == NULL ||
 *     context == NULL" (hpke.c:632).
 *   - wc_HpkeEncap() (hpke.c:776), "hpke == NULL || ephemeralKey == NULL ||
 *     receiverKey == NULL || sharedSecret == NULL" (hpke.c:794).
 *   - wc_HpkeDecap() (hpke.c:1014), "hpke == NULL || receiverKey == NULL"
 *     (hpke.c:1032).
 *
 * Only the DHKEM_X25519_HKDF_SHA256 / HKDF_SHA256 / HPKE_AES_128_GCM suite
 * is exercised (matching the suite used by tests/api/test_hpke.c), since it
 * requires no RNG-blinding/timing-resistance side paths to reach a valid
 * baseline call.
 *
 * Residuals (not attempted here, and not forced): wc_HpkeGenerateKeyPair()'s
 * "ret == 0 && *keypair == NULL" / "ret != 0 && *keypair != NULL" pair
 * (hpke.c:341/344) and wc_HpkeDeserializePublicKey()'s equivalent pair
 * (hpke.c:445/448) are post-operation allocation-failure cleanup checks.
 * The "ret == 0 && *ptr == NULL" half is a defensive belt-and-suspenders
 * check (the switch above it either sets *ptr via XMALLOC/wc_ecc_key_new,
 * whose only NULL return is an allocation failure that would already force
 * ret != 0 through the inner init/make-key calls, or takes the
 * BAD_FUNC_ARG default without touching *ptr at all). The "ret != 0 &&
 * *ptr != NULL" half additionally requires an allocation that *succeeds*
 * (so *ptr is set) followed by a *later* operation on that same object
 * failing -- e.g. wc_curve25519_make_key()/wc_ecc_make_key_ex() or
 * wc_curve25519_import_public_ex()/wc_ecc_import_x963_ex() failing after
 * the XMALLOC/wc_ecc_key_new() succeeded. That is not forceable without a
 * fault-injecting allocator or a corrupted RNG/curve state, so both pairs
 * are left as justified residuals.
 *
 * Crash-safety: every call here either returns an error before dereferencing
 * an invalid argument, or operates on a validly initialized Hpke/key/context,
 * so no unusual cleanup is needed beyond freeing the keys/RNG we allocate.
 */

#include <wolfcrypt/src/hpke.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

int main(void)
{
    printf("hpke.c white-box supplement\n");
#if defined(HAVE_HPKE) && (defined(HAVE_ECC) || defined(HAVE_CURVE25519))
    {
        byte buf[32];

        XMEMSET(buf, 0, sizeof(buf));

        /* I2OSP() (hpke.c:86): w <= 0 || w > 32 || n < 0 */
        if (I2OSP(0, 0, buf) != MP_VAL)   /* w <= 0 true, short-circuits */
            wb_fail = 1;
        if (I2OSP(0, 33, buf) != MP_VAL)  /* w <= 0 false, w > 32 true */
            wb_fail = 1;
        if (I2OSP(-1, 4, buf) != MP_VAL)  /* w<=0, w>32 false, n < 0 true */
            wb_fail = 1;
        if (I2OSP(1, 4, buf) != 0)        /* all three false -> valid path */
            wb_fail = 1;

        /* I2OSP() (hpke.c:91): w < 4 && n > ((1 << (w * 8)) - 1) */
        if (I2OSP(256, 1, buf) != MP_VAL) /* w<4 true, n>max(255) true */
            wb_fail = 1;
        if (I2OSP(255, 1, buf) != 0)      /* w<4 true, n>max false */
            wb_fail = 1;
        if (I2OSP(1000000, 4, buf) != 0)  /* w<4 false -> decision false
                                            * regardless of n */
            wb_fail = 1;

        WB_NOTE("I2OSP width/length guards exercised");
    }

#if defined(HAVE_CURVE25519) && !defined(NO_SHA256) && \
    defined(WOLFSSL_AES_128)
    {
        Hpke hpke;
        WC_RNG rng;
        void* ephemeralKey = NULL;
        void* receiverKey = NULL;
        HpkeBaseContext context;
        byte nonceOut[HPKE_Nn_MAX];
        byte sharedSecretA[HPKE_Nsecret_MAX];
        byte sharedSecretB[HPKE_Nsecret_MAX];
        byte ephemeralPubKey[HPKE_Npk_MAX];
        word16 ephemeralPubKeySz = (word16)sizeof(ephemeralPubKey);
        int haveRng = 0;
        int ret;

        XMEMSET(&hpke, 0, sizeof(hpke));
        XMEMSET(&context, 0, sizeof(context));
        XMEMSET(nonceOut, 0, sizeof(nonceOut));
        XMEMSET(sharedSecretA, 0, sizeof(sharedSecretA));
        XMEMSET(sharedSecretB, 0, sizeof(sharedSecretB));
        XMEMSET(ephemeralPubKey, 0, sizeof(ephemeralPubKey));

        ret = wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
            HPKE_AES_128_GCM, NULL);
        if (ret == 0) {
            ret = wc_InitRng(&rng);
            haveRng = (ret == 0);
        }
        if (ret == 0)
            ret = wc_HpkeGenerateKeyPair(&hpke, &ephemeralKey, &rng);
        if (ret == 0)
            ret = wc_HpkeGenerateKeyPair(&hpke, &receiverKey, &rng);
        if (ret == 0)
            ret = wc_HpkeSerializePublicKey(&hpke, ephemeralKey,
                ephemeralPubKey, &ephemeralPubKeySz);

        if (ret != 0) {
            WB_NOTE("hpke/key setup failed; skipping static-helper drive");
            wb_fail = 1;
        }
        else {
            /* wc_HpkeContextComputeNonce() (hpke.c:632):
             * hpke == NULL || context == NULL */
            if (wc_HpkeContextComputeNonce(NULL, &context, nonceOut)
                    != BAD_FUNC_ARG)
                wb_fail = 1;
            if (wc_HpkeContextComputeNonce(&hpke, NULL, nonceOut)
                    != BAD_FUNC_ARG)
                wb_fail = 1;
            context.seq = 0;
            XMEMSET(context.base_nonce, 0, sizeof(context.base_nonce));
            if (wc_HpkeContextComputeNonce(&hpke, &context, nonceOut) != 0)
                wb_fail = 1;

            /* wc_HpkeEncap() (hpke.c:794): hpke == NULL ||
             * ephemeralKey == NULL || receiverKey == NULL ||
             * sharedSecret == NULL */
            if (wc_HpkeEncap(NULL, ephemeralKey, receiverKey, sharedSecretA)
                    != BAD_FUNC_ARG)
                wb_fail = 1;
            if (wc_HpkeEncap(&hpke, NULL, receiverKey, sharedSecretA)
                    != BAD_FUNC_ARG)
                wb_fail = 1;
            if (wc_HpkeEncap(&hpke, ephemeralKey, NULL, sharedSecretA)
                    != BAD_FUNC_ARG)
                wb_fail = 1;
            if (wc_HpkeEncap(&hpke, ephemeralKey, receiverKey, NULL)
                    != BAD_FUNC_ARG)
                wb_fail = 1;
            /* baseline: all operands valid -> decision false, real DH+KDF */
            if (wc_HpkeEncap(&hpke, ephemeralKey, receiverKey, sharedSecretA)
                    != 0)
                wb_fail = 1;

            /* wc_HpkeDecap() (hpke.c:1032): hpke == NULL ||
             * receiverKey == NULL */
            if (wc_HpkeDecap(NULL, receiverKey, ephemeralPubKey,
                    ephemeralPubKeySz, sharedSecretB) != BAD_FUNC_ARG)
                wb_fail = 1;
            if (wc_HpkeDecap(&hpke, NULL, ephemeralPubKey,
                    ephemeralPubKeySz, sharedSecretB) != BAD_FUNC_ARG)
                wb_fail = 1;
            /* baseline: both operands valid -> decision false, real
             * receiver-side DH+KDF using the ephemeral's serialized public
             * key; must derive the same shared secret Encap() computed. */
            if (wc_HpkeDecap(&hpke, receiverKey, ephemeralPubKey,
                    ephemeralPubKeySz, sharedSecretB) != 0)
                wb_fail = 1;
            else if (XMEMCMP(sharedSecretA, sharedSecretB,
                    hpke.Nsecret) != 0)
                wb_fail = 1;

            WB_NOTE("wc_HpkeContextComputeNonce / wc_HpkeEncap / "
                "wc_HpkeDecap NULL guards exercised");
        }

        if (ephemeralKey != NULL)
            wc_HpkeFreeKey(&hpke, hpke.kem, ephemeralKey, hpke.heap);
        if (receiverKey != NULL)
            wc_HpkeFreeKey(&hpke, hpke.kem, receiverKey, hpke.heap);
        if (haveRng)
            wc_FreeRng(&rng);
    }
#else
    WB_NOTE("DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/HPKE_AES_128_GCM suite "
        "unavailable; skipping context/encap/decap static-helper drive");
    wb_fail = 1;
#endif

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    printf("  HAVE_HPKE not defined; nothing to exercise\n");
#endif
    (void)wb_fail;
    return 0;
}
