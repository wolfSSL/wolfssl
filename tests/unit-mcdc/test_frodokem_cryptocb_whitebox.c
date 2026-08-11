/* test_frodokem_cryptocb_whitebox.c
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
 * MC/DC crypto-callback white-box supplement for wolfcrypt/src/wc_frodokem.c.
 *
 * ELEVEN of this file's thirteen residuals are the SAME operand:
 *
 *     if ((ret == 0) && !cbHandled) { ... }
 *
 * repeated through MakeKey, Encapsulate and Decapsulate. `cbHandled` is
 * assigned in exactly one place,
 *
 *     #ifdef WOLF_CRYPTO_CB
 *     if ((ret == 0) && (key->devId != INVALID_DEVID)) {
 *         ret = wc_CryptoCb_MakePqcKemKey(...);
 *         cbHandled = (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE));
 *         ...
 *     #endif
 *
 * so the operand needs THREE things at once that no existing campaign vector
 * supplies: the build must define WOLF_CRYPTO_CB (it is now set in
 * campaign/configs/frodokem/user_settings.base.h), the key must carry a real
 * devId, and a registered device must actually service the request rather than
 * declining with CRYPTOCB_UNAVAILABLE. Miss any one and `cbHandled` is a
 * constant 0 -- not merely undriven, but with no false side to drive.
 *
 * This TU registers a device that services the three FrodoKEM PQC-KEM requests
 * and declines everything else (so the DRBG and every other primitive keep
 * their software path), then runs make/encapsulate/decapsulate once with the
 * device attached -- the `cbHandled == 1` rows -- and once with
 * INVALID_DEVID -- the `cbHandled == 0` rows the ordinary tests already
 * produce, repeated here so both halves land in ONE binary (HARD RULE 1).
 *
 * The device callback fills nothing in: it reports success and leaves the
 * caller's buffers untouched, exactly as a real offload that returns a status
 * the driver then checks. Nothing downstream consumes those buffers, because
 * the whole point of `cbHandled` is that wc_frodokem.c skips its own
 * computation on that path. No key produced under the device is ever used.
 *
 * TWO MORE RESIDUALS, NEITHER NEEDING THE DEVICE
 * ----------------------------------------------
 *   - `else if (((key->flags & FRODOKEM_FLAG_BOTH_SET) != FRODOKEM_FLAG_BOTH_SET)
 *      || ((key->flags & FRODOKEM_FLAG_PKH_SET) == 0))`
 *     The second operand needs BOTH_SET present while PKH_SET is absent. Every
 *     public path that sets one sets the other, so the combination is reachable
 *     only by writing key->flags directly -- which this TU can do because it
 *     #includes the .c and the field is not opaque here.
 *   - `if ((ret == 0) && (XMEMCMP(pkh, key->pkh, p->lenSec) != 0))`
 *     in frodokem_check_priv_key(). The TRUE row needs a decoded private key
 *     whose stored public-key hash does not match SHAKE(seedA || b); corrupting
 *     one byte of the encoded pkh field before decoding produces exactly that,
 *     and it is the check's whole reason for existing.
 *
 * VARIANT COVERAGE (HARD RULE 2): both frodokem variants compile this file;
 * where FrodoKEM or WOLF_CRYPTO_CB is absent it becomes a skip stub, and
 * main() always returns 0. Determinism (HARD RULE 3): a fixed number of
 * operations, no sweep, no clock.
 */

/* frodokem_check_priv_key()'s `(ret == 0)` operand needs a SHAKE failure: its
 * only assignment to ret is frodokem_shake_oneshot(). The interposers are armed
 * only inside wb_pkh_mismatch_rows(); everything else here runs disarmed. */
#include "mcdc_fault_hash.h"

#include <wolfcrypt/src/wc_frodokem.c>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#if defined(WOLFSSL_HAVE_FRODOKEM) && defined(WOLF_CRYPTO_CB)

#define WB_DEVID 0x46524B31   /* arbitrary, != INVALID_DEVID */

/* Services only the three FrodoKEM PQC-KEM requests; everything else is
 * declined so the DRBG and the rest of wolfCrypt stay on software. */
static int wb_cryptocb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;

    if ((info != NULL) && (info->algo_type == WC_ALGO_TYPE_PK)) {
        if ((info->pk.type == WC_PK_TYPE_PQC_KEM_KEYGEN) ||
                (info->pk.type == WC_PK_TYPE_PQC_KEM_ENCAPS) ||
                (info->pk.type == WC_PK_TYPE_PQC_KEM_DECAPS)) {
            /* Handled: report success without touching any caller buffer. */
            return 0;
        }
    }
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

/* First compiled key type; every `(ret == 0) && !cbHandled` site is shared by
 * all of them, so one is enough and the sweep stays cheap. */
static int wb_first_type(void)
{
#ifdef WOLFSSL_FRODOKEM_SHAKE
    return WC_FRODOKEM_640_SHAKE;
#elif defined(WOLFSSL_FRODOKEM_AES)
    return WC_FRODOKEM_640_AES;
#else
    return 0;
#endif
}

/* The cbHandled == 1 rows. */
static void wb_offload_rows(WC_RNG* rng, int type)
{
    FrodoKemKey key;
    byte        ct[FRODOKEM_MAX_CIPHER_TEXT_SIZE];
    byte        ss[FRODOKEM_MAX_LENSEC];
    word32      ctLen = (word32)sizeof(ct);

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(ss, 0, sizeof(ss));

    if (wc_FrodoKemKey_Init(&key, type, NULL, WB_DEVID) != 0) {
        WB_NOTE("Init with a device id failed; offload rows skipped");
        return;
    }
    (void)wc_FrodoKemKey_CipherTextSize(&key, &ctLen);

    if (wc_FrodoKemKey_MakeKey(&key, rng) != 0) {
        WB_NOTE("MakeKey did not accept the device's success report");
        wb_fail = 1;
    }
    if (wc_FrodoKemKey_Encapsulate(&key, ct, ss, rng) != 0) {
        WB_NOTE("Encapsulate did not accept the device's success report");
        wb_fail = 1;
    }
    if (wc_FrodoKemKey_Decapsulate(&key, ss, ct, ctLen) != 0) {
        WB_NOTE("Decapsulate did not accept the device's success report");
        wb_fail = 1;
    }

    wc_FrodoKemKey_Free(&key);
    WB_NOTE("crypto-callback offload rows exercised");
}

/* The cbHandled == 0 rows, in the SAME binary: the device is registered but
 * the key carries no device id, so the offload block is skipped entirely and
 * the software path runs. */
static void wb_software_rows(WC_RNG* rng, int type)
{
    FrodoKemKey key;
    byte        ct[FRODOKEM_MAX_CIPHER_TEXT_SIZE];
    byte        ss[FRODOKEM_MAX_LENSEC];
    byte        ss2[FRODOKEM_MAX_LENSEC];
    word32      ctLen = (word32)sizeof(ct);

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(ct, 0, sizeof(ct));
    XMEMSET(ss, 0, sizeof(ss));
    XMEMSET(ss2, 0, sizeof(ss2));

    if (wc_FrodoKemKey_Init(&key, type, NULL, INVALID_DEVID) != 0) {
        return;
    }
    (void)wc_FrodoKemKey_CipherTextSize(&key, &ctLen);
    if (wc_FrodoKemKey_MakeKey(&key, rng) == 0) {
        if (wc_FrodoKemKey_Encapsulate(&key, ct, ss, rng) == 0) {
            (void)wc_FrodoKemKey_Decapsulate(&key, ss2, ct, ctLen);
        }
    }
    wc_FrodoKemKey_Free(&key);
    WB_NOTE("software-path rows exercised");
}

#else

static void wb_offload_rows(WC_RNG* rng, int type)
{
    (void)rng; (void)type;
    WB_NOTE("WOLF_CRYPTO_CB not set in this variant; offload rows skipped");
}

static void wb_software_rows(WC_RNG* rng, int type)
{
    (void)rng; (void)type;
}

static int wb_first_type(void)
{
    return 0;
}

#endif /* WOLFSSL_HAVE_FRODOKEM && WOLF_CRYPTO_CB */

#ifdef WOLFSSL_HAVE_FRODOKEM

/* `((key->flags & FRODOKEM_FLAG_BOTH_SET) != FRODOKEM_FLAG_BOTH_SET) ||
 *  ((key->flags & FRODOKEM_FLAG_PKH_SET) == 0)`
 *
 * Operand 1 needs the first to be FALSE (both halves present) and itself TRUE
 * (the public-key hash missing). Nothing in the library ever leaves the key in
 * that state, so it is written here directly. Only the export entry point's own
 * state check runs; it returns BAD_STATE_E before touching key material. */
static void wb_flag_rows(WC_RNG* rng, int type)
{
    FrodoKemKey key;
    byte        out[FRODOKEM_MAX_PRIVATE_KEY_SIZE];
    int         savedFlags;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(out, 0, sizeof(out));

    if (wc_FrodoKemKey_Init(&key, type, NULL, INVALID_DEVID) != 0) {
        return;
    }
    if (wc_FrodoKemKey_MakeKey(&key, rng) != 0) {
        wc_FrodoKemKey_Free(&key);
        return;
    }

    savedFlags = key.flags;
    /* (F,T): both key halves present, public-key hash flag cleared. */
    key.flags &= ~FRODOKEM_FLAG_PKH_SET;
    if (wc_FrodoKemKey_EncodePrivateKey(&key, out,
            (word32)key.params->skSize) == 0) {
        WB_NOTE("EncodePrivateKey accepted a key with no public-key hash");
        wb_fail = 1;
    }
    key.flags = savedFlags;

    /* (T,-): a half missing -- the row the ordinary error tests produce. */
    key.flags &= ~FRODOKEM_FLAG_BOTH_SET;
    (void)wc_FrodoKemKey_EncodePrivateKey(&key, out,
        (word32)key.params->skSize);
    key.flags = savedFlags;

    wc_FrodoKemKey_Free(&key);
    WB_NOTE("private-key state-flag rows exercised");
}

/* frodokem_check_priv_key()'s stored-hash comparison. Decoding an encoded
 * private key whose trailing pkh field has been altered makes the comparison
 * differ while ret is still 0, which is the TRUE row the decoder is there to
 * produce and which no valid key can supply. */
static void wb_pkh_mismatch_rows(WC_RNG* rng, int type)
{
    FrodoKemKey key;
    FrodoKemKey k2;
    byte        enc[FRODOKEM_MAX_PRIVATE_KEY_SIZE];
    word32      skSize;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&k2, 0, sizeof(k2));
    XMEMSET(enc, 0, sizeof(enc));

    if (wc_FrodoKemKey_Init(&key, type, NULL, INVALID_DEVID) != 0) {
        return;
    }
    if (wc_FrodoKemKey_MakeKey(&key, rng) != 0) {
        wc_FrodoKemKey_Free(&key);
        return;
    }
    skSize = (word32)key.params->skSize;
    if (skSize > (word32)sizeof(enc) ||
            wc_FrodoKemKey_EncodePrivateKey(&key, enc, skSize) != 0) {
        wc_FrodoKemKey_Free(&key);
        return;
    }
    wc_FrodoKemKey_Free(&key);

    /* Matching hash: the FALSE row. */
    if (wc_FrodoKemKey_Init(&k2, type, NULL, INVALID_DEVID) == 0) {
        if (wc_FrodoKemKey_DecodePrivateKey(&k2, enc, skSize) != 0) {
            WB_NOTE("DecodePrivateKey rejected a key it had just encoded");
            wb_fail = 1;
        }
    }
    wc_FrodoKemKey_Free(&k2);

    /* Altered trailing pkh: the TRUE row. pkh is the last lenSec bytes. */
    enc[skSize - 1] ^= 0x01;
    XMEMSET(&k2, 0, sizeof(k2));
    if (wc_FrodoKemKey_Init(&k2, type, NULL, INVALID_DEVID) == 0) {
        if (wc_FrodoKemKey_DecodePrivateKey(&k2, enc, skSize) == 0) {
            WB_NOTE("DecodePrivateKey accepted an inconsistent stored hash");
            wb_fail = 1;
        }
    }
    wc_FrodoKemKey_Free(&k2);
    enc[skSize - 1] ^= 0x01;

    /* The first operand's FALSE row: frodokem_shake_oneshot() itself fails, so
     * the comparison is never reached. It is the only assignment to ret in
     * frodokem_check_priv_key(), and it does not allocate -- hence the hash
     * interposer rather than the allocator one. A short dense sweep covers the
     * handful of SHAKE calls the decode path makes. */
    {
        long n;

        for (n = 1; n <= 8L; n++) {
            XMEMSET(&k2, 0, sizeof(k2));
            if (wc_FrodoKemKey_Init(&k2, type, NULL, INVALID_DEVID) == 0) {
                mcdc_fh_arm(n);
                (void)wc_FrodoKemKey_DecodePrivateKey(&k2, enc, skSize);
                mcdc_fh_disarm();
            }
            wc_FrodoKemKey_Free(&k2);
        }
        mcdc_fh_disarm();
    }

    WB_NOTE("stored public-key-hash consistency rows exercised");
}

#else

static void wb_flag_rows(WC_RNG* rng, int type)
{
    (void)rng; (void)type;
}

static void wb_pkh_mismatch_rows(WC_RNG* rng, int type)
{
    (void)rng; (void)type;
}

#endif /* WOLFSSL_HAVE_FRODOKEM */

int main(void)
{
    WC_RNG rng;
    int    type = wb_first_type();

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wc_frodokem.c crypto-callback white-box supplement\n");

#if defined(WOLFSSL_HAVE_FRODOKEM)
    XMEMSET(&rng, 0, sizeof(rng));
    if (wc_InitRng(&rng) != 0) {
        printf("  wc_InitRng failed; nothing driven\n");
        printf("done (skipped)\n");
        return 0;
    }

#ifdef WOLF_CRYPTO_CB
    if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cryptocb, NULL) != 0) {
        WB_NOTE("device registration failed; offload rows skipped");
    }
    else {
        wb_offload_rows(&rng, type);
        wb_software_rows(&rng, type);
        wc_CryptoCb_UnRegisterDevice(WB_DEVID);
    }
#else
    (void)wb_offload_rows; (void)wb_software_rows;
#endif

    wb_flag_rows(&rng, type);
    wb_pkh_mismatch_rows(&rng, type);

    wc_FreeRng(&rng);
#else
    (void)rng; (void)type;
    printf("  FrodoKEM not compiled in; nothing to do\n");
#endif

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* A non-zero exit makes the campaign discard this binary's coverage. */
    return 0;
}
