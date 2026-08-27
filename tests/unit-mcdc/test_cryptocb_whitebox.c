/* test_cryptocb_whitebox.c
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
 * MC/DC white-box supplement for wolfcrypt/src/cryptocb.c.
 *
 * cryptocb.c is the crypto-callback dispatch framework (gated
 * WOLF_CRYPTO_CB). It has roughly eighty file-internal wc_CryptoCb_<Algo>()
 * dispatch functions, each of which is WOLFSSL_LOCAL (not exported from the
 * shared library) and therefore cannot be reached directly from tests/api.
 * Almost every one of these functions opens with the same guard, once the
 * registered device for the key/arg's devId has been located:
 *
 *     dev = wc_CryptoCb_FindDevice(<devId>, <algoType>);
 *     if (dev && dev->cb) { ... call dev->cb(...) ... }
 *
 * MC/DC of `dev && dev->cb` needs three vectors, once per dispatch function:
 *   - dev != NULL, cb != NULL   (T,T)  a registered device WITH a callback
 *   - dev == NULL               (F)    an unregistered devId
 *   - dev != NULL, cb == NULL   (T,F)  a registered device whose cb is NULL
 * wc_CryptoCb_RegisterDevice() stores dev->cb = cb even when cb == NULL, so
 * all three are reachable by registering one device with a callback and one
 * without.
 *
 * A single software callback (wb_cb) is registered; it ignores its
 * arguments and always returns CRYPTOCB_UNAVAILABLE, so every dispatch
 * function's `if (dev && dev->cb)` body runs (dev->cb is invoked) and
 * returns cleanly without ever touching the algorithm payload buffers.
 * That means the key/context structs passed in only need their `devId`
 * field to be readable - the guard is evaluated, dev->cb is invoked (or
 * skipped), and the function returns before any payload pointer is
 * dereferenced. Zero-initialized stack structs are therefore sufficient
 * everywhere *except* wc_CryptoCb_EccMakePub/EccCheckPubKey, which read
 * key->dp (and, for CheckPubKey, key->pubkey's mp_int state) *before*
 * reaching the guard; those two use a real wc_ecc_init_ex()+wc_ecc_set_curve()
 * key so key->dp is valid.
 *
 * IMPORTANT PITFALL (why this file does NOT use INVALID_DEVID for the F
 * vector): wc_CryptoCb_GetDevice() is a linear scan for
 * `gCryptoDev[i].devId == devId` with no special case for INVALID_DEVID.
 * Every *free* (unregistered) table slot is left holding
 * devId == INVALID_DEVID by wc_CryptoCb_ClearDev(). So looking up
 * INVALID_DEVID matches the first free slot and returns a non-NULL `dev`
 * whose `->cb` is NULL - i.e. it lands on (T,F), not F!
 * (wc_CryptoCb_IsDeviceRegistered(), just above wc_CryptoCb_GetDevice() in
 * cryptocb.c, has to special-case `devId == INVALID_DEVID` for exactly this
 * reason - see its comment.) Using INVALID_DEVID as the "unregistered"
 * vector here would silently double up the (T,F) case and never actually
 * demonstrate the `dev == NULL` independence pair. Instead, WB_DEVID_NONE
 * below is an ordinary devId value that is never registered and is not
 * INVALID_DEVID, which correctly makes wc_CryptoCb_FindDevice() return NULL.
 *
 * Coverage in this file: RSA (including the WOLF_CRYPTO_CB_RSA_PAD
 * RsaPad/RsaPssVerify pair), ECC, Curve25519, Curve448, Ed25519, Ed448,
 * AES (GCM/CCM/CBC/CTR/CFB/OFB/ECB/SetKey/KeyWrap/KeyUnWrap), DES3,
 * the hash family
 * (SHA/SHA224/SHA256/SHA384/SHA512/SHA3/SHAKE),
 * HMAC, RNG (RandomBlock/RandomSeed), GetCert, CMAC,
 * HKDF (extract/expand/two-step-CMAC), the generic Copy/Free/SetKey/
 * ExportKey callbacks, and the ML-KEM / ML-DSA PQC dispatch functions.
 * wc_SHE (WOLFSSL_SHE) and the LMS/XMSS/FALCON/SLHDSA/FRODOKEM PQC families
 * are left as residuals - they need family-specific key setup (wc_SHE,
 * LmsKey, XmssKey, falcon_key, SlhDsaKey) that is out of scope for this
 * pass; see the WB_NOTE calls below for exactly which are skipped.
 *
 * Crash-safety: wb_cb() always returns CRYPTOCB_UNAVAILABLE before touching
 * `info`, so every `if (dev && dev->cb)` body returns immediately after the
 * call; no payload buffer is ever read or written by the callback. All
 * wc_CryptoCb_* return values are discarded (this is a crash-safety pass,
 * not a correctness assertion pass).
 *
 * Second pass - extra arg-validation / post-cb guards: beyond the top-level
 * `dev && dev->cb` guard, a handful of dispatch functions have additional
 * decisions either in front of it (arg validation, e.g. EccMakePub's
 * `key == NULL || pubOut == NULL || key->dp == NULL`) or after the dev->cb
 * call (e.g. SHA-384/SHA-512's `ret == 0 && digest != NULL` post-processing
 * of the SHA-512-core fallback). These are driven with a REGISTERED devId
 * (so `dev && dev->cb` is already true) while varying only the extra
 * argument, so reachability does not depend on the dispatch guard at all.
 * The SHA-384/SHA-512 post-cb guards additionally need dev->cb to return 0
 * (success) for the fallback attempt specifically - see wb_cb_hash_fallback_ok
 * below for how that is done without needing to inject a fault mid-dispatch.
 *
 * Third pass - the first-registered-device fallback guard at cryptocb.c
 * :1159 / :1189, `if ((dev == NULL || dev->cb == NULL) &&
 * (devId == INVALID_DEVID)) dev = wc_CryptoCb_FindDeviceByIndex(0);` in
 * wc_CryptoCb_Curve25519MakePub() and wc_CryptoCb_Curve25519Generic().
 * The third operand keeps a caller that named a device from having its
 * private scalar handed to a different one; it is driven directly by the
 * devId argument, TRUE for every vector below except the dedicated
 * `devId != INVALID_DEVID` one at the end of the section. The first two
 * operands are driven purely by the state of the gCryptoDev[] table, with
 * the lookup issued for INVALID_DEVID so the third operand holds:
 *   - (F,T)  at least one free slot exists. wc_CryptoCb_ClearDev() leaves
 *            free slots at devId == INVALID_DEVID with cb == NULL, so
 *            wc_CryptoCb_GetDevice(INVALID_DEVID) returns that slot:
 *            dev != NULL but dev->cb == NULL.
 *   - (T,-)  every one of MAX_CRYPTO_DEVID_CALLBACKS slots is registered, so
 *            no slot holds INVALID_DEVID and wc_CryptoCb_GetDevice() returns
 *            NULL. This is reachable with the public registration API alone.
 *   - (F,F)  needs a lookup that yields a device with a non-NULL callback.
 *            wc_CryptoCb_RegisterDevice() explicitly refuses devId ==
 *            INVALID_DEVID ("INVALID_DEVID marks a free slot"), so no free
 *            slot can ever carry a callback and the plain lookup cannot
 *            produce this state. The supported mechanism that can is
 *            WOLF_CRYPTO_CB_FIND: wc_CryptoCb_FindDevice() first passes the
 *            requested devId through the registered find callback, so a find
 *            callback that maps INVALID_DEVID onto a real registered devId
 *            makes the lookup return a device WITH a callback. Neither infra
 *            variant's user_settings defines WOLF_CRYPTO_CB_FIND, so this
 *            file compiles it in for its own translation unit, exactly the
 *            way test_memory_whitebox.c compiles WOLFSSL_STATIC_MEMORY in for
 *            memory.c. It costs nothing in denominator: the only code the
 *            macro adds to cryptocb.c is a file-static pointer, the setter
 *            wc_CryptoCb_SetDeviceFindCb(), and a SINGLE-condition
 *            `if (CryptoCb_FindCb != NULL)` inside wc_CryptoCb_FindDevice()
 *            (single-condition decisions carry no MC/DC conditions), and it
 *            changes no struct layout shared with the linked archive.
 *            The find callback is installed only around the (F,F) vectors and
 *            reset to NULL immediately afterwards, so every other decision in
 *            this file is evaluated with CryptoCb_FindCb == NULL, i.e. with
 *            wc_CryptoCb_FindDevice() behaving exactly as in the shipped
 *            variants.
 *
 * Fourth pass - wc_CryptoCb_RegisterDevice()'s free-slot scan,
 * `devId == INVALID_DEVID && cb == NULL` in wc_CryptoCb_GetFreeDevice().
 * The (T,F) half of the pair - a slot part way through registration, with
 * cb already set but devId not yet published - exists only transiently
 * inside a WOLF_CRYPTO_CB_CMD register command, so the vector plants it
 * directly in gCryptoDev[]; see the section just before the final
 * unregisters. (T,T) is every successful registration in this file and
 * (F,-) every occupied slot the scan walks past.
 */

/* See the "third pass" note above: compiled in for this TU only, so the
 * :1159/:1189 (F,F) vector can be driven through the public
 * wc_CryptoCb_SetDeviceFindCb() API. Must precede the #include below. */
#ifndef WOLF_CRYPTO_CB_FIND
#define WOLF_CRYPTO_CB_FIND
#endif

#include <wolfcrypt/src/cryptocb.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

#ifdef WOLF_CRYPTO_CB

/* Three-vector MC/DC pattern for every `dev && dev->cb` guard, see header
 * comment above for why WB_DEVID_NONE (not INVALID_DEVID) is the F vector. */
#define WB_DEVID       1
#define WB_DEVID_NOCB  2
#define WB_DEVID_NONE  424242

/* Base devId for the MAX_CRYPTO_DEVID_CALLBACKS "fill the whole table"
 * registrations used by the :1159/:1189 (T,-) vector. Distinct from every
 * other devId in this file and never equal to INVALID_DEVID. */
#define WB_DEVID_FILL  500

static int wb_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)info;
    (void)ctx;
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

/* Second devId/callback pair used only to reach the extra arg-validation and
 * post-dev->cb "ret == 0" processing guards that sit inside a handful of
 * dispatch bodies (SHA-384/SHA-512's narrow-variant-then-generic-core
 * fallback). wb_cb above always fails, so `ret == 0` can never be shown TRUE
 * through it - the SHA-384/SHA-512 dispatch functions call dev->cb *twice*
 * (once for the narrow variant type, e.g. SHA-384 or SHA-512/224, then again
 * for the generic SHA-512 core type if the first attempt reports
 * CRYPTOCB_UNAVAILABLE), so a callback that fails only for the narrow-variant
 * attempt and succeeds for the generic one exercises both the "fall through"
 * path and the post-cb ret==0 processing, without ever needing a fault to be
 * injected mid-dispatch. */
#define WB_DEVID_HASH_OK 3

static int wb_cb_hash_fallback_ok(int devId, wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;
    if (info != NULL && info->algo_type == WC_ALGO_TYPE_HASH &&
            info->hash.type == WC_HASH_TYPE_SHA512) {
        return 0;
    }
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}

#ifdef WOLF_CRYPTO_CB_FIND
/* Find callback used ONLY by the :1159/:1189 (F,F) vectors. It rewrites the
 * INVALID_DEVID lookup that wc_CryptoCb_Curve25519MakePub/Generic issue into
 * WB_DEVID, which is registered with wb_cb, so wc_CryptoCb_FindDevice()
 * returns a device whose ->cb is non-NULL. Installed and removed around
 * those two calls only. */
static int wb_find_cb(int devId, int algoType)
{
    (void)devId;
    (void)algoType;
    return WB_DEVID;
}
#endif /* WOLF_CRYPTO_CB_FIND */

/* WB_DRIVE3(lvalue, call): sets `lvalue` (a struct field or plain local
 * devId variable) to each of the three vectors and issues `call` once per
 * vector. One invocation completes the `dev && dev->cb` MC/DC independence
 * pairs for one dispatch function. Return values are discarded. */
#define WB_DRIVE3(lvalue, call) \
    do { \
        (lvalue) = WB_DEVID;      (void)(call); \
        (lvalue) = WB_DEVID_NONE; (void)(call); \
        (lvalue) = WB_DEVID_NOCB; (void)(call); \
    } while (0)

#endif /* WOLF_CRYPTO_CB */

int main(void)
{
    printf("cryptocb.c white-box supplement\n");
#ifdef WOLF_CRYPTO_CB
    /* generic scratch buffers reused across families below */
    byte in[64];
    byte out[64];
    byte out2[64];
    byte tag[16];
    byte nonce[12];
    byte smallKey[16];
    word32 outLen;
    int res = 0;
    int intSize = 0;
    int devId = 0;

    XMEMSET(in, 0, sizeof(in));
    XMEMSET(out, 0, sizeof(out));
    XMEMSET(out2, 0, sizeof(out2));
    XMEMSET(tag, 0, sizeof(tag));
    XMEMSET(nonce, 0, sizeof(nonce));
    XMEMSET(smallKey, 0, sizeof(smallKey));

    /* gCryptoDev is a plain static array; its BSS zero-init leaves every
     * slot's devId == 0, not INVALID_DEVID. wc_CryptoCb_RegisterDevice()
     * looks for a free slot via wc_CryptoCb_GetFreeDevice(), so
     * without this call every registration below fails with BUFFER_E ("out
     * of devices") - none of the BSS-zeroed slots match INVALID_DEVID.
     * wc_CryptoCb_Init() marks all slots devId == INVALID_DEVID, matching
     * the state the real library leaves them in after startup. */
    wc_CryptoCb_Init();

    if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
        wb_fail = 1;
    if (wc_CryptoCb_RegisterDevice(WB_DEVID_NOCB, NULL, NULL) != 0)
        wb_fail = 1;
    if (wc_CryptoCb_RegisterDevice(WB_DEVID_HASH_OK, wb_cb_hash_fallback_ok,
            NULL) != 0)
        wb_fail = 1;

    /* ---- RSA ---- */
#ifndef NO_RSA
    {
        RsaKey rsaKey;
        XMEMSET(&rsaKey, 0, sizeof(rsaKey));

        outLen = sizeof(out);
        WB_DRIVE3(rsaKey.devId, wc_CryptoCb_Rsa(in, sizeof(in), out,
            &outLen, RSA_PUBLIC_ENCRYPT, &rsaKey, NULL));

#ifdef WOLF_CRYPTO_CB_RSA_PAD
        outLen = sizeof(out);
        WB_DRIVE3(rsaKey.devId, wc_CryptoCb_RsaPad(in, sizeof(in), out,
            &outLen, RSA_PUBLIC_ENCRYPT, &rsaKey, NULL, NULL));

        outLen = sizeof(out2);
        WB_DRIVE3(rsaKey.devId, wc_CryptoCb_RsaPssVerify(in, sizeof(in),
            in, sizeof(in), WC_HASH_TYPE_SHA256, 0, 0, &rsaKey, &res,
            out2, sizeof(out2), &outLen));
#endif

#ifdef WOLFSSL_KEY_GEN
        WB_DRIVE3(rsaKey.devId,
            wc_CryptoCb_MakeRsaKey(&rsaKey, 2048, WC_RSA_EXPONENT, NULL));
#endif

        WB_DRIVE3(rsaKey.devId,
            wc_CryptoCb_RsaCheckPrivKey(&rsaKey, NULL, 0));

        WB_DRIVE3(rsaKey.devId,
            wc_CryptoCb_RsaGetSize(&rsaKey, &intSize));

        WB_NOTE("RSA: Rsa/RsaPad/MakeRsaKey/RsaCheckPrivKey/RsaGetSize "
                "dev&&dev->cb driven");
    }
#else
    WB_NOTE("NO_RSA defined; RSA dispatch skipped");
#endif /* !NO_RSA */

    /* ---- ECC ---- */
#ifdef HAVE_ECC
    {
        ecc_key eccKey;
        ecc_key eccKey2;
        int haveDp;

        XMEMSET(&eccKey, 0, sizeof(eccKey));
        XMEMSET(&eccKey2, 0, sizeof(eccKey2));
        (void)wc_ecc_init_ex(&eccKey, NULL, 0);
        (void)wc_ecc_init_ex(&eccKey2, NULL, 0);
        haveDp = (wc_ecc_set_curve(&eccKey, 32, ECC_CURVE_DEF) == 0);

#ifdef HAVE_ECC_DHE
        WB_DRIVE3(eccKey.devId, wc_CryptoCb_MakeEccKey(NULL, 32, &eccKey,
            ECC_SECP256R1));

        outLen = sizeof(out);
        WB_DRIVE3(eccKey.devId,
            wc_CryptoCb_Ecdh(&eccKey, &eccKey2, out, &outLen));
#endif

#ifdef HAVE_ECC_SIGN
        outLen = sizeof(out);
        WB_DRIVE3(eccKey.devId, wc_CryptoCb_EccSign(in, sizeof(in), out,
            &outLen, NULL, &eccKey));
#endif

#ifdef HAVE_ECC_VERIFY
        WB_DRIVE3(eccKey.devId, wc_CryptoCb_EccVerify(out, sizeof(out), in,
            sizeof(in), &res, &eccKey));
#endif

#ifdef HAVE_ECC_CHECK_KEY
        WB_DRIVE3(eccKey.devId,
            wc_CryptoCb_EccCheckPrivKey(&eccKey, NULL, 0));
#endif

        WB_DRIVE3(eccKey.devId, wc_CryptoCb_EccGetSize(&eccKey, &intSize));
        WB_DRIVE3(eccKey.devId, wc_CryptoCb_EccGetSigSize(&eccKey, &intSize));

        if (haveDp) {
            ecc_point pubOutPt;
            ecc_key eccKeyNoDp;
            XMEMSET(&pubOutPt, 0, sizeof(pubOutPt));
            WB_DRIVE3(eccKey.devId,
                wc_CryptoCb_EccMakePub(&eccKey, &pubOutPt));

#ifdef HAVE_ECC_CHECK_KEY
            WB_DRIVE3(eccKey.devId,
                wc_CryptoCb_EccCheckPubKey(&eccKey, 0, 0));
#endif
            WB_NOTE("ECC: EccMakePub/EccCheckPubKey dev&&dev->cb driven "
                    "(key->dp populated via wc_ecc_set_curve)");

            /* Residual: EccMakePub's own arg-validation guard
             * "key == NULL || pubOut == NULL || key->dp == NULL" sits BEFORE
             * dev && dev->cb, so it is driven with a registered devId and
             * only the arg under test varied. The all-valid (all-false) case
             * is already covered by the WB_DRIVE3 call above. */
            XMEMSET(&eccKeyNoDp, 0, sizeof(eccKeyNoDp));
            (void)wc_ecc_init_ex(&eccKeyNoDp, NULL, 0); /* dp left NULL */
            eccKeyNoDp.devId = WB_DEVID;
            (void)wc_CryptoCb_EccMakePub(NULL, &pubOutPt);      /* key==NULL */
            eccKey.devId = WB_DEVID;
            (void)wc_CryptoCb_EccMakePub(&eccKey, NULL);        /* pubOut==NULL */
            (void)wc_CryptoCb_EccMakePub(&eccKeyNoDp, &pubOutPt); /* dp==NULL */

#ifdef HAVE_ECC_CHECK_KEY
            /* Residual: EccCheckPubKey's "key == NULL || key->dp == NULL". */
            (void)wc_CryptoCb_EccCheckPubKey(NULL, 0, 0);         /* key==NULL */
            (void)wc_CryptoCb_EccCheckPubKey(&eccKeyNoDp, 0, 0);  /* dp==NULL */
#endif
            WB_NOTE("ECC: EccMakePub/EccCheckPubKey arg-validation guard "
                    "(key==NULL / pubOut==NULL / key->dp==NULL) driven");
            WB_NOTE("RESIDUAL: EccMakePub's post-cb \"outSz != ptSz || "
                    "buf[0] != ECC_POINT_UNCOMP\" (only reached when "
                    "dev->cb returns 0) not driven - none of our callbacks "
                    "return success for a WC_PK_TYPE_EC_MAKE_PUB request, "
                    "and safely hitting the FALSE case needs a callback "
                    "that writes a correctly-sized X9.63 buffer into the "
                    "internal heap-allocated buf/outSz exposed via "
                    "cryptoInfo.pk.ecc_make_pub, then a genuinely mp_init'd "
                    "ecc_point (not the zeroed pubOutPt used above) so the "
                    "subsequent mp_read_unsigned_bin calls are safe; left "
                    "out of scope for this pass rather than risk it");
        }
        else {
            WB_NOTE("ECC: wc_ecc_set_curve failed; EccMakePub/"
                    "EccCheckPubKey skipped (key->dp guard unreachable)");
        }

        WB_NOTE("ECC: MakeEccKey/Ecdh/EccSign/EccVerify/EccCheckPrivKey/"
                "EccGetSize/EccGetSigSize dev&&dev->cb driven");
    }
#else
    WB_NOTE("HAVE_ECC not defined; ECC dispatch skipped");
#endif /* HAVE_ECC */

    /* ---- Curve25519 ---- */
#ifdef HAVE_CURVE25519
    {
        curve25519_key c1;
        curve25519_key c2;
        XMEMSET(&c1, 0, sizeof(c1));
        XMEMSET(&c2, 0, sizeof(c2));
        (void)wc_curve25519_init_ex(&c1, NULL, 0);
        (void)wc_curve25519_init_ex(&c2, NULL, 0);

        WB_DRIVE3(c1.devId,
            wc_CryptoCb_Curve25519Gen(NULL, CURVE25519_KEYSIZE, &c1));

        outLen = sizeof(out);
        WB_DRIVE3(c1.devId, wc_CryptoCb_Curve25519(&c1, &c2, out, &outLen,
            EC25519_LITTLE_ENDIAN));

        WB_NOTE("Curve25519: Curve25519Gen/Curve25519 dev&&dev->cb driven");
    }
#else
    WB_NOTE("HAVE_CURVE25519 not defined; Curve25519 dispatch skipped");
#endif /* HAVE_CURVE25519 */

    /* ---- Curve448 ---- */
#ifdef HAVE_CURVE448
    {
        curve448_key c4a;
        curve448_key c4b;
        XMEMSET(&c4a, 0, sizeof(c4a));
        XMEMSET(&c4b, 0, sizeof(c4b));
        (void)wc_curve448_init_ex(&c4a, NULL, 0);
        (void)wc_curve448_init_ex(&c4b, NULL, 0);

        WB_DRIVE3(c4a.devId,
            wc_CryptoCb_Curve448Gen(NULL, CURVE448_KEY_SIZE, &c4a));

        outLen = sizeof(out);
        WB_DRIVE3(c4a.devId, wc_CryptoCb_Curve448(&c4a, &c4b, out, &outLen,
            EC448_LITTLE_ENDIAN));

        WB_NOTE("Curve448: Curve448Gen/Curve448 dev&&dev->cb driven");
    }
#else
    WB_NOTE("HAVE_CURVE448 not defined; Curve448 dispatch skipped");
#endif /* HAVE_CURVE448 */

    /* ---- Ed25519 ---- */
#ifdef HAVE_ED25519
    {
        ed25519_key e1;
        byte edPub[ED25519_PUB_KEY_SIZE];
        XMEMSET(&e1, 0, sizeof(e1));
        XMEMSET(edPub, 0, sizeof(edPub));
        (void)wc_ed25519_init_ex(&e1, NULL, 0);

        WB_DRIVE3(e1.devId,
            wc_CryptoCb_Ed25519Gen(NULL, ED25519_KEY_SIZE, &e1));

        outLen = sizeof(out);
        WB_DRIVE3(e1.devId, wc_CryptoCb_Ed25519Sign(in, sizeof(in), out,
            &outLen, &e1, 0, NULL, 0));

        WB_DRIVE3(e1.devId, wc_CryptoCb_Ed25519Verify(out, sizeof(out), in,
            sizeof(in), &res, &e1, 0, NULL, 0));

        WB_DRIVE3(e1.devId,
            wc_CryptoCb_Ed25519MakePub(&e1, edPub, sizeof(edPub)));

        WB_DRIVE3(e1.devId, wc_CryptoCb_Ed25519CheckKey(&e1));

        WB_NOTE("Ed25519: Gen/Sign/Verify/MakePub/CheckKey dev&&dev->cb "
                "driven");

        /* Residual: Ed25519MakePub's arg-validation guard
         * "key == NULL || pubKey == NULL || pubKeySz != ED25519_PUB_KEY_SIZE"
         * sits before dev && dev->cb; drive it with a registered devId and
         * only the arg under test varied. The all-valid (all-false) case is
         * already covered by the WB_DRIVE3 call above. */
        e1.devId = WB_DEVID;
        (void)wc_CryptoCb_Ed25519MakePub(NULL, edPub, sizeof(edPub));
        (void)wc_CryptoCb_Ed25519MakePub(&e1, NULL, ED25519_PUB_KEY_SIZE);
        (void)wc_CryptoCb_Ed25519MakePub(&e1, edPub, 1); /* wrong size */
        WB_NOTE("Ed25519: Ed25519MakePub arg-validation guard "
                "(key==NULL / pubKey==NULL / pubKeySz!=SIZE) driven");
    }
#else
    WB_NOTE("HAVE_ED25519 not defined; Ed25519 dispatch skipped");
#endif /* HAVE_ED25519 */

    /* ---- Ed448 ---- */
#ifdef HAVE_ED448
    {
        ed448_key e4;
        XMEMSET(&e4, 0, sizeof(e4));
        (void)wc_ed448_init_ex(&e4, NULL, 0);

        outLen = sizeof(out);
        WB_DRIVE3(e4.devId, wc_CryptoCb_Ed448Sign(in, sizeof(in), out,
            &outLen, &e4, 0, NULL, 0));

        WB_DRIVE3(e4.devId, wc_CryptoCb_Ed448Verify(out, sizeof(out), in,
            sizeof(in), &res, &e4, 0, NULL, 0));

        WB_NOTE("Ed448: Ed448Sign/Ed448Verify dev&&dev->cb driven");
    }
#else
    WB_NOTE("HAVE_ED448 not defined; Ed448 dispatch skipped");
#endif /* HAVE_ED448 */

    /* ---- AES ---- */
#ifndef NO_AES
    {
        Aes aes;
        XMEMSET(&aes, 0, sizeof(aes));

#ifdef HAVE_AESGCM
        WB_DRIVE3(aes.devId, wc_CryptoCb_AesGcmEncrypt(&aes, out2, in,
            sizeof(in), nonce, sizeof(nonce), tag, sizeof(tag), NULL, 0));
        WB_DRIVE3(aes.devId, wc_CryptoCb_AesGcmDecrypt(&aes, out2, in,
            sizeof(in), nonce, sizeof(nonce), tag, sizeof(tag), NULL, 0));
#endif

#ifdef HAVE_AESCCM
        WB_DRIVE3(aes.devId, wc_CryptoCb_AesCcmEncrypt(&aes, out2, in,
            sizeof(in), nonce, sizeof(nonce), tag, sizeof(tag), NULL, 0));
        WB_DRIVE3(aes.devId, wc_CryptoCb_AesCcmDecrypt(&aes, out2, in,
            sizeof(in), nonce, sizeof(nonce), tag, sizeof(tag), NULL, 0));
#endif

#ifdef HAVE_AES_CBC
        WB_DRIVE3(aes.devId,
            wc_CryptoCb_AesCbcEncrypt(&aes, out2, in, sizeof(in)));
        WB_DRIVE3(aes.devId,
            wc_CryptoCb_AesCbcDecrypt(&aes, out2, in, sizeof(in)));
#endif

#ifdef WOLFSSL_AES_COUNTER
        WB_DRIVE3(aes.devId,
            wc_CryptoCb_AesCtrEncrypt(&aes, out2, in, sizeof(in)));
#endif

#ifdef WOLFSSL_AES_CFB
        WB_DRIVE3(aes.devId,
            wc_CryptoCb_AesCfbEncrypt(&aes, out2, in, sizeof(in)));
        WB_DRIVE3(aes.devId,
            wc_CryptoCb_AesCfbDecrypt(&aes, out2, in, sizeof(in)));
#endif

#ifdef WOLFSSL_AES_OFB
        WB_DRIVE3(aes.devId,
            wc_CryptoCb_AesOfbEncrypt(&aes, out2, in, sizeof(in)));
        WB_DRIVE3(aes.devId,
            wc_CryptoCb_AesOfbDecrypt(&aes, out2, in, sizeof(in)));
#endif

#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
        WB_DRIVE3(aes.devId,
            wc_CryptoCb_AesEcbEncrypt(&aes, out2, in, sizeof(in)));
        WB_DRIVE3(aes.devId,
            wc_CryptoCb_AesEcbDecrypt(&aes, out2, in, sizeof(in)));
#endif

#ifdef WOLF_CRYPTO_CB_AES_SETKEY
        /* wc_CryptoCb_AesSetKey() also requires aes->devId != INVALID_DEVID
         * to reach the dev&&dev->cb guard; none of WB_DEVID/WB_DEVID_NONE/
         * WB_DEVID_NOCB equal INVALID_DEVID, so all three vectors clear it
         * the same way every other dispatch function does. */
        WB_DRIVE3(aes.devId,
            wc_CryptoCb_AesSetKey(&aes, smallKey, sizeof(smallKey)));
#endif

#ifdef HAVE_AES_KEYWRAP
        /* wc_CryptoCb_AesKeyWrap/AesKeyUnWrap resolve their device from
         * aes->devId when aes != NULL, so the standard three-vector sweep
         * applies. wb_cb returns CRYPTOCB_UNAVAILABLE, so the post-dispatch
         * "device reports the wrapped length" block is not entered and no
         * payload buffer is read. */
        WB_DRIVE3(aes.devId, wc_CryptoCb_AesKeyWrap(&aes, in, sizeof(in),
            out2, sizeof(out2), nonce, 0));
        WB_DRIVE3(aes.devId, wc_CryptoCb_AesKeyUnWrap(&aes, in, sizeof(in),
            out2, sizeof(out2), nonce, 0));
#endif

        WB_NOTE("AES: GCM/CCM/CBC/CTR/CFB/OFB/ECB/SetKey/KeyWrap "
                "(as compiled) dev&&dev->cb driven");
    }
#else
    WB_NOTE("NO_AES defined; AES dispatch skipped");
#endif /* !NO_AES */

    /* ---- DES3 ---- */
#ifndef NO_DES3
    {
        Des3 des3;
        XMEMSET(&des3, 0, sizeof(des3));

        WB_DRIVE3(des3.devId,
            wc_CryptoCb_Des3Encrypt(&des3, out2, in, 8));
        WB_DRIVE3(des3.devId,
            wc_CryptoCb_Des3Decrypt(&des3, out2, in, 8));

        WB_NOTE("DES3: Des3Encrypt/Des3Decrypt dev&&dev->cb driven");
    }
#else
    WB_NOTE("NO_DES3 defined; DES3 dispatch skipped");
#endif /* !NO_DES3 */

    /* ---- Hashes ---- */
#ifndef NO_SHA
    {
        wc_Sha sha;
        XMEMSET(&sha, 0, sizeof(sha));
        WB_DRIVE3(sha.devId,
            wc_CryptoCb_ShaHash(&sha, in, sizeof(in), out));
        WB_NOTE("SHA-1: ShaHash dev&&dev->cb driven");
    }
#else
    WB_NOTE("NO_SHA defined; SHA-1 dispatch skipped");
#endif

#ifdef WOLFSSL_SHA224
    {
        wc_Sha224 sha224;
        XMEMSET(&sha224, 0, sizeof(sha224));
        WB_DRIVE3(sha224.devId,
            wc_CryptoCb_Sha224Hash(&sha224, in, sizeof(in), out));
        WB_NOTE("SHA-224: Sha224Hash dev&&dev->cb driven");
    }
#else
    WB_NOTE("WOLFSSL_SHA224 not defined; SHA-224 dispatch skipped");
#endif

#ifndef NO_SHA256
    {
        wc_Sha256 sha256;
        XMEMSET(&sha256, 0, sizeof(sha256));
        WB_DRIVE3(sha256.devId,
            wc_CryptoCb_Sha256Hash(&sha256, in, sizeof(in), out));
        WB_NOTE("SHA-256: Sha256Hash dev&&dev->cb driven");
    }
#else
    WB_NOTE("NO_SHA256 defined; SHA-256 dispatch skipped");
#endif

#ifdef WOLFSSL_SHA384
    {
        wc_Sha384 sha384;
        byte digest384[WC_SHA384_DIGEST_SIZE];
        XMEMSET(&sha384, 0, sizeof(sha384));
        XMEMSET(digest384, 0, sizeof(digest384));
        /* digest == NULL: the SHA-512 fallback's post-cb truncation/IV
         * rewrite code is guarded on "ret == 0 && digest != NULL", which
         * wb_cb's non-zero return already keeps unreachable regardless. */
        WB_DRIVE3(sha384.devId,
            wc_CryptoCb_Sha384Hash(&sha384, in, sizeof(in), NULL));
        WB_NOTE("SHA-384: Sha384Hash dev&&dev->cb driven (both the direct "
                "and SHA-512-fallback dev->cb call sites)");

        /* Residual: the fallback's "ret == 0 && digest != NULL" post-cb
         * guard. wb_cb (above) always fails, so ret == 0 is never reachable
         * through it. wb_cb_hash_fallback_ok fails only for the narrow
         * WC_HASH_TYPE_SHA384 attempt (so the dispatch function falls
         * through to the generic SHA-512-core attempt, exactly as it would
         * for a real partial-capability device) and succeeds for that
         * generic attempt, so ret == 0 is reached without any fault
         * injection. Both operands are flipped independently: */
        sha384.devId = WB_DEVID_HASH_OK;
        (void)wc_CryptoCb_Sha384Hash(&sha384, in, sizeof(in), digest384);
        /* ret==0(T), digest!=NULL(T) */
        sha384.devId = WB_DEVID_HASH_OK;
        (void)wc_CryptoCb_Sha384Hash(&sha384, in, sizeof(in), NULL);
        /* ret==0(T), digest!=NULL(F) */
        sha384.devId = WB_DEVID;
        (void)wc_CryptoCb_Sha384Hash(&sha384, in, sizeof(in), digest384);
        /* ret==0(F), digest!=NULL(T) */
        WB_NOTE("SHA-384: Sha384Hash post-cb \"ret==0 && digest!=NULL\" "
                "guard driven both ways (via wb_cb_hash_fallback_ok)");
    }
#else
    WB_NOTE("WOLFSSL_SHA384 not defined; SHA-384 dispatch skipped");
#endif

#ifdef WOLFSSL_SHA512
    {
        wc_Sha512 sha512;
        byte digest512[WC_SHA512_DIGEST_SIZE];
        XMEMSET(&sha512, 0, sizeof(sha512));
        XMEMSET(digest512, 0, sizeof(digest512));
        WB_DRIVE3(sha512.devId,
            wc_CryptoCb_Sha512Hash(&sha512, in, sizeof(in), NULL
#if !(defined(HAVE_FIPS) && FIPS_VERSION_LT(7,0))
                , WC_SHA512_DIGEST_SIZE
#endif
                ));
        WB_NOTE("SHA-512: Sha512Hash dev&&dev->cb driven");

#if !(defined(HAVE_FIPS) && FIPS_VERSION_LT(7,0))
        /* Residuals: the generic-core post-cb guards
         *   ret==0 && digest!=NULL && digestSz!=WC_SHA512_DIGEST_SIZE
         *   sha512!=NULL && digestSz==WC_SHA512_224_DIGEST_SIZE
         *   sha512!=NULL && digestSz==WC_SHA512_256_DIGEST_SIZE
         * As with SHA-384 above, ret==0 needs wb_cb_hash_fallback_ok (it
         * fails the narrow SHA-512/224 or SHA-512/256 attempt so the
         * function falls through to the generic SHA-512 attempt, then
         * succeeds there). digestSz is driven through an arbitrary size
         * that is none of the three special sizes (20), then each of the
         * 224/256 special sizes in turn, so every ==/!= comparison flips
         * both ways while sha512 stays a valid non-NULL struct throughout. */
        sha512.devId = WB_DEVID_HASH_OK;
        (void)wc_CryptoCb_Sha512Hash(&sha512, in, sizeof(in), digest512, 20);
        /* ret==0(T), digest!=NULL(T), digestSz!=64(T); digestSz!=224,!=256 */
        sha512.devId = WB_DEVID;
        (void)wc_CryptoCb_Sha512Hash(&sha512, in, sizeof(in), digest512, 20);
        /* ret==0(F) - independence pair for the ret operand above */
        sha512.devId = WB_DEVID_HASH_OK;
        (void)wc_CryptoCb_Sha512Hash(&sha512, in, sizeof(in), NULL, 20);
        /* digest!=NULL(F), ret==0(T), digestSz!=64(T) - independence pair
         * for the digest!=NULL operand (held against the digestSz=20/HASH_OK
         * vector above, which has digest!=NULL(T)) */
        sha512.devId = WB_DEVID_HASH_OK;
        (void)wc_CryptoCb_Sha512Hash(&sha512, in, sizeof(in), digest512,
            WC_SHA512_DIGEST_SIZE);
        /* digestSz!=64(F), ret==0(T), digest!=NULL(T) - independence pair
         * for the digestSz!=64 operand (both here and in the adjacent
         * "use local buffer if not full size" guard just above it) */
#ifndef WOLFSSL_NOSHA512_224
        sha512.devId = WB_DEVID_HASH_OK;
        (void)wc_CryptoCb_Sha512Hash(&sha512, in, sizeof(in), digest512,
            WC_SHA512_224_DIGEST_SIZE);
        /* digestSz==224(T), sha512!=NULL(T) */
#endif
#ifndef WOLFSSL_NOSHA512_256
        sha512.devId = WB_DEVID_HASH_OK;
        (void)wc_CryptoCb_Sha512Hash(&sha512, in, sizeof(in), digest512,
            WC_SHA512_256_DIGEST_SIZE);
        /* digestSz==256(T), sha512!=NULL(T) */
#endif
        WB_NOTE("SHA-512: Sha512Hash generic-core post-cb "
                "ret==0/digest!=NULL/digestSz guards driven (via "
                "wb_cb_hash_fallback_ok)");

        /* Residual: the "sha512 != NULL" half of the 224/256 IV-rewrite
         * guards (sha512 != NULL && digestSz == ...SIZE) can only be shown
         * FALSE by calling with sha512 == NULL - and wc_CryptoCb_Sha512Hash
         * falls back to wc_CryptoCb_FindDeviceByIndex(0) (first registered
         * device in table order) whenever sha512 == NULL, rather than using
         * a struct's devId field. To land that lookup on the
         * hash-fallback-ok device deterministically, temporarily unregister
         * the other two devices (so index 0 can only resolve to
         * WB_DEVID_HASH_OK), issue the sha512==NULL calls, then restore the
         * other two devices for the rest of this file. */
        wc_CryptoCb_UnRegisterDevice(WB_DEVID);
        wc_CryptoCb_UnRegisterDevice(WB_DEVID_NOCB);
#ifndef WOLFSSL_NOSHA512_224
        (void)wc_CryptoCb_Sha512Hash(NULL, in, sizeof(in), digest512,
            WC_SHA512_224_DIGEST_SIZE); /* sha512==NULL(F), digestSz==224(T) */
#endif
#ifndef WOLFSSL_NOSHA512_256
        (void)wc_CryptoCb_Sha512Hash(NULL, in, sizeof(in), digest512,
            WC_SHA512_256_DIGEST_SIZE); /* sha512==NULL(F), digestSz==256(T) */
#endif
        if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
            wb_fail = 1;
        if (wc_CryptoCb_RegisterDevice(WB_DEVID_NOCB, NULL, NULL) != 0)
            wb_fail = 1;
        WB_NOTE("SHA-512: 224/256 IV-rewrite guards' sha512!=NULL operand "
                "driven both ways (temporarily isolating "
                "wb_cb_hash_fallback_ok at table index 0)");
#else
        WB_NOTE("SHA-512: pre-digestSz-param FIPS<7.0 build; post-cb "
                "digestSz guards not applicable/skipped");
#endif
    }
#else
    WB_NOTE("WOLFSSL_SHA512 not defined; SHA-512 dispatch skipped");
#endif

#if defined(WOLFSSL_SHA3) && (!defined(HAVE_FIPS) || FIPS_VERSION_GE(6, 0))
    {
        wc_Sha3 sha3;
        XMEMSET(&sha3, 0, sizeof(sha3));
        WB_DRIVE3(sha3.devId, wc_CryptoCb_Sha3Hash(&sha3,
            WC_HASH_TYPE_SHA3_256, in, sizeof(in), out));
        WB_NOTE("SHA3: Sha3Hash dev&&dev->cb driven");

#if defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)
        outLen = sizeof(out);
        WB_DRIVE3(sha3.devId, wc_CryptoCb_Shake(&sha3,
#if defined(WOLFSSL_SHAKE128)
            WC_HASH_TYPE_SHAKE128,
#else
            WC_HASH_TYPE_SHAKE256,
#endif
            in, sizeof(in), out, outLen));
        WB_NOTE("SHAKE: Shake dev&&dev->cb driven");
#endif
    }
#else
    WB_NOTE("WOLFSSL_SHA3 not defined/available; SHA3/SHAKE dispatch "
            "skipped");
#endif

    /* ---- HMAC ---- */
#ifndef NO_HMAC
    {
        Hmac hmac;
        XMEMSET(&hmac, 0, sizeof(hmac));
        WB_DRIVE3(hmac.devId, wc_CryptoCb_Hmac(&hmac, WC_HASH_TYPE_SHA256,
            in, sizeof(in), out));
        WB_NOTE("HMAC: Hmac dev&&dev->cb driven");
    }
#else
    WB_NOTE("NO_HMAC defined; HMAC dispatch skipped");
#endif

    /* ---- RNG ---- */
#ifndef WC_NO_RNG
    {
        WC_RNG rng;
        OS_Seed os;
        XMEMSET(&rng, 0, sizeof(rng));
        XMEMSET(&os, 0, sizeof(os));

        WB_DRIVE3(rng.devId,
            wc_CryptoCb_RandomBlock(&rng, out, sizeof(out)));

        /* wc_CryptoCb_RandomSeed() has no NULL check on `os` at all, unlike
         * every other dispatch function here - it always dereferences
         * os->devId, so `os` must always be a valid non-NULL pointer. */
        WB_DRIVE3(os.devId, wc_CryptoCb_RandomSeed(&os, out, sizeof(out)));

        WB_NOTE("RNG: RandomBlock/RandomSeed dev&&dev->cb driven");
    }
#else
    WB_NOTE("WC_NO_RNG defined; RNG dispatch skipped");
#endif

    /* ---- Cert ---- */
#ifndef NO_CERTS
    {
        byte* certOut = NULL;
        word32 certOutSz = 0;
        int certFmt = 0;

        WB_DRIVE3(devId, wc_CryptoCb_GetCert(devId, "label", 5, NULL, 0,
            &certOut, &certOutSz, &certFmt, NULL));

        WB_NOTE("Cert: GetCert dev&&dev->cb driven");
    }
#else
    WB_NOTE("NO_CERTS defined; GetCert dispatch skipped");
#endif

    /* ---- CMAC ---- */
#ifdef WOLFSSL_CMAC
    {
        Cmac cmac;
        XMEMSET(&cmac, 0, sizeof(cmac));
        outLen = sizeof(out);
        WB_DRIVE3(cmac.devId, wc_CryptoCb_Cmac(&cmac, NULL, 0, in,
            sizeof(in), out, &outLen, WC_CMAC_AES, NULL));
        WB_NOTE("CMAC: Cmac dev&&dev->cb driven");
    }
#else
    WB_NOTE("WOLFSSL_CMAC not defined; CMAC dispatch skipped");
#endif

    /* ---- HKDF / two-step CMAC KDF ---- */
#if defined(HAVE_HKDF) && !defined(NO_HMAC)
    WB_DRIVE3(devId, wc_CryptoCb_Hkdf(WC_HASH_TYPE_SHA256, in, sizeof(in),
        NULL, 0, NULL, 0, out, sizeof(out), devId));
    WB_DRIVE3(devId, wc_CryptoCb_Hkdf_Extract(WC_HASH_TYPE_SHA256, NULL, 0,
        in, sizeof(in), out, devId));
    WB_DRIVE3(devId, wc_CryptoCb_Hkdf_Expand(WC_HASH_TYPE_SHA256, in,
        sizeof(in), NULL, 0, out, sizeof(out), devId));
    WB_NOTE("KDF: Hkdf/Hkdf_Extract/Hkdf_Expand dev&&dev->cb driven");
#else
    WB_NOTE("HAVE_HKDF && !NO_HMAC not both defined; HKDF dispatch "
            "skipped");
#endif

#if defined(HAVE_CMAC_KDF)
    WB_DRIVE3(devId, wc_CryptoCb_Kdf_TwostepCmac(NULL, 0, in, sizeof(in),
        NULL, 0, out, sizeof(out), devId));
    WB_NOTE("KDF: Kdf_TwostepCmac dev&&dev->cb driven");
#else
    WB_NOTE("HAVE_CMAC_KDF not defined; two-step CMAC KDF dispatch "
            "skipped");
#endif

    /* ---- generic Copy/Free/SetKey/ExportKey callbacks ---- */
#ifdef WOLF_CRYPTO_CB_COPY
    WB_DRIVE3(devId, wc_CryptoCb_Copy(devId, WC_ALGO_TYPE_HASH,
        WC_HASH_TYPE_SHA256, NULL, NULL));
    WB_NOTE("Copy: wc_CryptoCb_Copy dev&&dev->cb driven");
#else
    WB_NOTE("WOLF_CRYPTO_CB_COPY not defined; Copy dispatch skipped");
#endif

#ifdef WOLF_CRYPTO_CB_FREE
    WB_DRIVE3(devId, wc_CryptoCb_Free(devId, WC_ALGO_TYPE_HASH,
        WC_HASH_TYPE_SHA256, 0, NULL));
    WB_NOTE("Free: wc_CryptoCb_Free dev&&dev->cb driven");
#else
    WB_NOTE("WOLF_CRYPTO_CB_FREE not defined; Free dispatch skipped");
#endif

#ifdef WOLF_CRYPTO_CB_SETKEY
    WB_DRIVE3(devId, wc_CryptoCb_SetKey(devId, WC_SETKEY_AES, NULL, NULL, 0,
        NULL, 0, 0));
    WB_NOTE("SetKey: wc_CryptoCb_SetKey dev&&dev->cb driven");
#else
    WB_NOTE("WOLF_CRYPTO_CB_SETKEY not defined; SetKey dispatch skipped");
#endif

#ifdef WOLF_CRYPTO_CB_EXPORT_KEY
    WB_DRIVE3(devId,
        wc_CryptoCb_ExportKey(devId, WC_PK_TYPE_RSA, NULL, NULL));
    WB_NOTE("ExportKey: wc_CryptoCb_ExportKey dev&&dev->cb driven");
#else
    WB_NOTE("WOLF_CRYPTO_CB_EXPORT_KEY not defined; ExportKey dispatch "
            "skipped");
#endif

    /* ---- PQC: ML-KEM ---- */
#if defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_HAVE_FRODOKEM)
#ifdef WOLFSSL_HAVE_MLKEM
    {
        MlKemKey mlkem;
        XMEMSET(&mlkem, 0, sizeof(mlkem));

        WB_DRIVE3(mlkem.devId, wc_CryptoCb_MakePqcKemKey(NULL,
            WC_PQC_KEM_TYPE_MLKEM, 512, &mlkem));
        WB_DRIVE3(mlkem.devId, wc_CryptoCb_PqcEncapsulate(out, sizeof(out),
            out2, sizeof(out2), NULL, WC_PQC_KEM_TYPE_MLKEM, &mlkem));
        WB_DRIVE3(mlkem.devId, wc_CryptoCb_PqcDecapsulate(out, sizeof(out),
            out2, sizeof(out2), WC_PQC_KEM_TYPE_MLKEM, &mlkem));

        /* bonus: an unrecognized `type` leaves wc_CryptoCb_PqcKemGetDevId()
         * at its INVALID_DEVID default, driving the "devId == INVALID_DEVID"
         * early-return guard that sits in front of the dev&&dev->cb check
         * in each of these functions. */
        mlkem.devId = WB_DEVID;
        (void)wc_CryptoCb_MakePqcKemKey(NULL, -1, 512, &mlkem);

        WB_NOTE("PQC ML-KEM: MakePqcKemKey/PqcEncapsulate/PqcDecapsulate "
                "dev&&dev->cb driven, plus GetDevId's INVALID_DEVID guard");
    }
#else
    WB_NOTE("WOLFSSL_HAVE_MLKEM not defined (only FRODOKEM); ML-KEM/"
            "FrodoKEM dispatch skipped - FrodoKEM key setup out of scope");
#endif
#else
    WB_NOTE("Neither WOLFSSL_HAVE_MLKEM nor WOLFSSL_HAVE_FRODOKEM defined; "
            "PQC KEM dispatch skipped");
#endif

    /* ---- PQC: ML-DSA ---- */
#if defined(HAVE_FALCON) || defined(WOLFSSL_HAVE_MLDSA) || \
    defined(WOLFSSL_HAVE_SLHDSA)
#ifdef WOLFSSL_HAVE_MLDSA
    {
        wc_MlDsaKey mldsa;
        XMEMSET(&mldsa, 0, sizeof(mldsa));

        WB_DRIVE3(mldsa.devId, wc_CryptoCb_MakePqcSignatureKey(NULL,
            WC_PQC_SIG_TYPE_MLDSA, 65, &mldsa));

        outLen = sizeof(out);
        WB_DRIVE3(mldsa.devId, wc_CryptoCb_PqcSign(in, sizeof(in), out,
            &outLen, NULL, 0, 0, NULL, WC_PQC_SIG_TYPE_MLDSA, &mldsa));

        WB_DRIVE3(mldsa.devId, wc_CryptoCb_PqcVerify(out, sizeof(out), in,
            sizeof(in), NULL, 0, 0, &res, WC_PQC_SIG_TYPE_MLDSA, &mldsa));

        WB_DRIVE3(mldsa.devId, wc_CryptoCb_PqcSignatureCheckPrivKey(&mldsa,
            WC_PQC_SIG_TYPE_MLDSA, NULL, 0));

        /* bonus: same INVALID_DEVID early-return guard as ML-KEM above */
        mldsa.devId = WB_DEVID;
        (void)wc_CryptoCb_MakePqcSignatureKey(NULL, -1, 65, &mldsa);

        WB_NOTE("PQC ML-DSA: MakePqcSignatureKey/PqcSign/PqcVerify/"
                "PqcSignatureCheckPrivKey dev&&dev->cb driven, plus "
                "GetDevId's INVALID_DEVID guard");
    }
#else
    WB_NOTE("WOLFSSL_HAVE_MLDSA not defined (only FALCON/SLHDSA); "
            "Falcon/SLH-DSA dispatch skipped - their key setup is out of "
            "scope for this pass");
#endif
#else
    WB_NOTE("None of HAVE_FALCON/WOLFSSL_HAVE_MLDSA/WOLFSSL_HAVE_SLHDSA "
            "defined; PQC signature dispatch skipped");
#endif

    /* ---- residuals: not driven in this pass ---- */
#if defined(WOLFSSL_HAVE_LMS) || defined(WOLFSSL_HAVE_XMSS)
    WB_NOTE("RESIDUAL: PqcStatefulSig{KeyGen,Sign,Verify,SigsLeft} "
            "(LMS/XMSS) not driven - needs LmsKey/XmssKey-specific setup, "
            "out of scope for this pass");
#endif
#ifdef WOLFSSL_SHE
    WB_NOTE("RESIDUAL: wc_CryptoCb_She* family not driven - needs wc_SHE "
            "key-slot state, out of scope for this pass");
#endif

    /* ---- ECIES encrypt/decrypt dispatch (HAVE_ECC_ENCRYPT) ----
     * Both bodies resolve their device from privKey->devId and then take the
     * usual `if (dev && dev->cb)` guard, so the standard three-vector sweep
     * applies. Nothing but privKey->devId is read before the guard, and the
     * registered callback (wb_cb) ignores the wc_CryptoInfo it is handed and
     * reports CRYPTOCB_UNAVAILABLE, so a zeroed ecc_key with no key material
     * is sufficient and safe here -- no curve arithmetic runs. */
#ifdef HAVE_ECC_ENCRYPT
    {
        ecc_key  ecPriv;
        byte     eciesMsg[16];
        byte     eciesOut[128];
        word32   eciesOutSz;

        XMEMSET(&ecPriv, 0, sizeof(ecPriv));
        XMEMSET(eciesMsg, 0x5e, sizeof(eciesMsg));
        XMEMSET(eciesOut, 0, sizeof(eciesOut));

        eciesOutSz = (word32)sizeof(eciesOut);
        WB_DRIVE3(ecPriv.devId,
            wc_CryptoCb_EciesEncrypt(&ecPriv, NULL, eciesMsg,
                (word32)sizeof(eciesMsg), eciesOut, &eciesOutSz, NULL, 0));

        eciesOutSz = (word32)sizeof(eciesOut);
        WB_DRIVE3(ecPriv.devId,
            wc_CryptoCb_EciesDecrypt(&ecPriv, NULL, eciesMsg,
                (word32)sizeof(eciesMsg), eciesOut, &eciesOutSz, NULL));

        /* privKey == NULL early return (both entry points). */
        eciesOutSz = (word32)sizeof(eciesOut);
        (void)wc_CryptoCb_EciesEncrypt(NULL, NULL, eciesMsg,
                (word32)sizeof(eciesMsg), eciesOut, &eciesOutSz, NULL, 0);
        (void)wc_CryptoCb_EciesDecrypt(NULL, NULL, eciesMsg,
                (word32)sizeof(eciesMsg), eciesOut, &eciesOutSz, NULL);

        WB_NOTE("ECIES Encrypt/Decrypt dev&&dev->cb three-vector driven");
    }
#else
    WB_NOTE("HAVE_ECC_ENCRYPT not defined; ECIES dispatch skipped");
#endif

    /* ---- Curve25519 MakePub / Generic ----
     * These take an explicit devId and resolve a device with
     * FindDevice(devId), falling back to FindDeviceByIndex(0) only when the
     * caller passed INVALID_DEVID. The calls below all pass INVALID_DEVID, so
     * their `if (dev && dev->cb)` guard is driven by what is registered
     * rather than by the argument. Run last, since the rows below deregister
     * everything. */
#ifdef HAVE_CURVE25519
    {
        byte c25pub[CURVE25519_KEYSIZE];
        byte c25priv[CURVE25519_KEYSIZE];
        byte c25base[CURVE25519_KEYSIZE];

        XMEMSET(c25pub, 0, sizeof(c25pub));
        XMEMSET(c25priv, 1, sizeof(c25priv));
        XMEMSET(c25base, 9, sizeof(c25base));

        /* Argument guards: one operand true per call, then all false. The
         * device state is irrelevant here -- each returns before resolving. */
        (void)wc_CryptoCb_Curve25519MakePub(INVALID_DEVID, sizeof(c25pub), NULL,
                sizeof(c25priv), c25priv);
        (void)wc_CryptoCb_Curve25519MakePub(INVALID_DEVID, sizeof(c25pub),
                c25pub, sizeof(c25priv), NULL);
        (void)wc_CryptoCb_Curve25519Generic(INVALID_DEVID, sizeof(c25pub), NULL,
                sizeof(c25priv), c25priv, sizeof(c25base), c25base);
        (void)wc_CryptoCb_Curve25519Generic(INVALID_DEVID, sizeof(c25pub),
                c25pub, sizeof(c25priv), NULL, sizeof(c25base), c25base);
        (void)wc_CryptoCb_Curve25519Generic(INVALID_DEVID, sizeof(c25pub),
                c25pub, sizeof(c25priv), c25priv, sizeof(c25base), NULL);

        /* `dev && dev->cb` (T,T): a registered device with a callback is the
         * first slot FindDeviceByIndex(0) reaches. */
        (void)wc_CryptoCb_Curve25519MakePub(INVALID_DEVID, sizeof(c25pub),
                c25pub, sizeof(c25priv), c25priv);
        (void)wc_CryptoCb_Curve25519Generic(INVALID_DEVID, sizeof(c25pub),
                c25pub, sizeof(c25priv), c25priv, sizeof(c25base), c25base);

        /* (T,F): the only registered device has a NULL callback. */
        wc_CryptoCb_UnRegisterDevice(WB_DEVID);
        wc_CryptoCb_UnRegisterDevice(WB_DEVID_HASH_OK);
        (void)wc_CryptoCb_Curve25519MakePub(INVALID_DEVID, sizeof(c25pub),
                c25pub, sizeof(c25priv), c25priv);
        (void)wc_CryptoCb_Curve25519Generic(INVALID_DEVID, sizeof(c25pub),
                c25pub, sizeof(c25priv), c25priv, sizeof(c25base), c25base);

        /* (F,-): nothing registered at all, so FindDeviceByIndex returns NULL
         * and the guard short-circuits on its first operand. */
        wc_CryptoCb_UnRegisterDevice(WB_DEVID_NOCB);
        (void)wc_CryptoCb_Curve25519MakePub(INVALID_DEVID, sizeof(c25pub),
                c25pub, sizeof(c25priv), c25priv);
        (void)wc_CryptoCb_Curve25519Generic(INVALID_DEVID, sizeof(c25pub),
                c25pub, sizeof(c25priv), c25priv, sizeof(c25base), c25base);

        /* Put the callback device back for anything that follows. */
        if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
            wb_fail = 1;
        WB_NOTE("Curve25519MakePub/Generic: arg guards and dev&&dev->cb "
                "driven across registered/no-callback/none states");
    }
#else
    WB_NOTE("HAVE_CURVE25519 not defined; Curve25519MakePub/Generic skipped");
#endif

    /* ---- Curve25519MakePub/Generic: `dev == NULL || dev->cb == NULL`
     * (cryptocb.c :1159 and :1189) ----
     * Three vectors, all in this binary; see the "third pass" note in the
     * file header for why each table state produces the operand values it
     * does. Each vector rebuilds the table from wc_CryptoCb_Init() so the
     * preceding section's leftovers cannot influence it. Nothing here can
     * touch the key buffers: whichever device the guard ends up selecting,
     * its callback is wb_cb, which returns CRYPTOCB_UNAVAILABLE without
     * reading the wc_CryptoInfo it is handed. */
#ifdef HAVE_CURVE25519
    {
        byte g25pub[CURVE25519_KEYSIZE];
        byte g25priv[CURVE25519_KEYSIZE];
        byte g25base[CURVE25519_KEYSIZE];
        int slot;

        XMEMSET(g25pub, 0, sizeof(g25pub));
        XMEMSET(g25priv, 1, sizeof(g25priv));
        XMEMSET(g25base, 9, sizeof(g25base));

        /* (F,T): one device registered, so free slots remain. The
         * INVALID_DEVID lookup lands on the first free slot: non-NULL, cb
         * NULL. Guard TRUE, so FindDeviceByIndex(0) supplies the device. */
        wc_CryptoCb_Init();
        if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
            wb_fail = 1;
        (void)wc_CryptoCb_Curve25519MakePub(INVALID_DEVID, sizeof(g25pub),
                g25pub, sizeof(g25priv), g25priv);
        (void)wc_CryptoCb_Curve25519Generic(INVALID_DEVID, sizeof(g25pub),
                g25pub, sizeof(g25priv), g25priv, sizeof(g25base), g25base);

        /* (T,-): every slot registered, so no slot holds INVALID_DEVID and
         * wc_CryptoCb_GetDevice(INVALID_DEVID) returns NULL. dev == NULL is
         * TRUE and short-circuits the OR - the independence pair for the
         * first operand against the (F,T) vector above. */
        wc_CryptoCb_Init();
        for (slot = 0; slot < MAX_CRYPTO_DEVID_CALLBACKS; slot++) {
            if (wc_CryptoCb_RegisterDevice(WB_DEVID_FILL + slot, wb_cb,
                    NULL) != 0)
                wb_fail = 1;
        }
        (void)wc_CryptoCb_Curve25519MakePub(INVALID_DEVID, sizeof(g25pub),
                g25pub, sizeof(g25priv), g25priv);
        (void)wc_CryptoCb_Curve25519Generic(INVALID_DEVID, sizeof(g25pub),
                g25pub, sizeof(g25priv), g25priv, sizeof(g25base), g25base);

        /* (F,F): the find callback rewrites the INVALID_DEVID lookup into
         * WB_DEVID, which is registered with wb_cb, so the lookup returns a
         * device WITH a callback - the independence pair for the second
         * operand against the (F,T) vector above. */
#ifdef WOLF_CRYPTO_CB_FIND
        wc_CryptoCb_Init();
        if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
            wb_fail = 1;
        wc_CryptoCb_SetDeviceFindCb(wb_find_cb);
        (void)wc_CryptoCb_Curve25519MakePub(INVALID_DEVID, sizeof(g25pub),
                g25pub, sizeof(g25priv), g25priv);
        (void)wc_CryptoCb_Curve25519Generic(INVALID_DEVID, sizeof(g25pub),
                g25pub, sizeof(g25priv), g25priv, sizeof(g25base), g25base);
        wc_CryptoCb_SetDeviceFindCb(NULL);
        WB_NOTE("Curve25519MakePub/Generic: dev==NULL||dev->cb==NULL "
                "[:1159,:1189] driven (F,T) / (T,-) / (F,F)");
#else
        WB_NOTE("Curve25519MakePub/Generic: dev==NULL||dev->cb==NULL "
                "[:1159,:1189] driven (F,T) / (T,-); (F,F) needs "
                "WOLF_CRYPTO_CB_FIND, not compiled here");
#endif

        /* devId != INVALID_DEVID with the first two operands genuinely left
         * in the (F,T) state of the vector above: WB_DEVID_NOCB is
         * registered with a NULL callback, so the lookup returns a non-NULL
         * slot (dev == NULL FALSE) whose cb is NULL (dev->cb == NULL TRUE).
         * Only the third operand changes, so this is a unique-cause
         * independence pair. The caller named a device that cannot serve the
         * request, so the fallback must not run and the scalar goes
         * nowhere. */
        wc_CryptoCb_Init();
        if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
            wb_fail = 1;
        if (wc_CryptoCb_RegisterDevice(WB_DEVID_NOCB, NULL, NULL) != 0)
            wb_fail = 1;
        (void)wc_CryptoCb_Curve25519MakePub(WB_DEVID_NOCB, sizeof(g25pub),
                g25pub, sizeof(g25priv), g25priv);
        (void)wc_CryptoCb_Curve25519Generic(WB_DEVID_NOCB, sizeof(g25pub),
                g25pub, sizeof(g25priv), g25priv, sizeof(g25base), g25base);
        WB_NOTE("Curve25519MakePub/Generic: devId==INVALID_DEVID "
                "[:1159,:1189] driven false against the (F,T) vector");

        /* Leave the table the way the rest of this file expects it. */
        wc_CryptoCb_Init();
        if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
            wb_fail = 1;
    }
#else
    WB_NOTE("HAVE_CURVE25519 not defined; :1159/:1189 vectors skipped");
#endif

    /* ---- Curve448MakePub / Curve448Generic ----
     * Unlike their Curve25519 counterparts these take an explicit devId, so
     * the fallback guard is
     *     (dev == NULL || dev->cb == NULL) && (devId == INVALID_DEVID)
     * and every operand is driven from the argument plus the table state:
     *   devId = WB_DEVID       -> dev found WITH a callback: (F,F,-), guard
     *                             false, and the following dev && dev->cb is
     *                             (T,T).
     *   devId = WB_DEVID_NOCB  -> dev found with a NULL callback: (F,T,F),
     *                             guard false because the devId names a
     *                             device, and dev && dev->cb is (T,F).
     *   devId = WB_DEVID_NONE  -> no such device: (T,-,F), guard false, and
     *                             dev && dev->cb is (F,-).
     *   devId = INVALID_DEVID, free slots present -> the lookup lands on a
     *                             free slot (non-NULL, cb NULL): (F,T,T),
     *                             guard true, FindDeviceByIndex(0) supplies
     *                             the device.
     *   devId = INVALID_DEVID, every slot registered -> no slot holds
     *                             INVALID_DEVID so the lookup returns NULL:
     *                             (T,-,T), guard true.
     * The last two rebuild the table, so this runs after everything above.
     * Whichever device the guard selects, its callback is wb_cb, which
     * returns CRYPTOCB_UNAVAILABLE without reading the wc_CryptoInfo. */
#ifdef HAVE_CURVE448
    {
        byte c4pub[CURVE448_PUB_KEY_SIZE];
        byte c4priv[CURVE448_KEY_SIZE];
        byte c4base[CURVE448_KEY_SIZE];
        int slot;

        XMEMSET(c4pub, 0, sizeof(c4pub));
        XMEMSET(c4priv, 1, sizeof(c4priv));
        XMEMSET(c4base, 5, sizeof(c4base));

        wc_CryptoCb_Init();
        if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
            wb_fail = 1;
        if (wc_CryptoCb_RegisterDevice(WB_DEVID_NOCB, NULL, NULL) != 0)
            wb_fail = 1;

        /* Argument guards: one operand true per call. The device state is
         * irrelevant here -- each returns before resolving a device. */
        (void)wc_CryptoCb_Curve448MakePub(WB_DEVID, sizeof(c4pub), NULL,
                sizeof(c4priv), c4priv);
        (void)wc_CryptoCb_Curve448MakePub(WB_DEVID, sizeof(c4pub), c4pub,
                sizeof(c4priv), NULL);
        (void)wc_CryptoCb_Curve448Generic(WB_DEVID, sizeof(c4pub), NULL,
                sizeof(c4priv), c4priv, sizeof(c4base), c4base);
        (void)wc_CryptoCb_Curve448Generic(WB_DEVID, sizeof(c4pub), c4pub,
                sizeof(c4priv), NULL, sizeof(c4base), c4base);
        (void)wc_CryptoCb_Curve448Generic(WB_DEVID, sizeof(c4pub), c4pub,
                sizeof(c4priv), c4priv, sizeof(c4base), NULL);

        /* All arguments valid from here on, so the argument guards are all
         * false and the device guards below are the ones being varied. */
        (void)wc_CryptoCb_Curve448MakePub(WB_DEVID, sizeof(c4pub), c4pub,
                sizeof(c4priv), c4priv);
        (void)wc_CryptoCb_Curve448Generic(WB_DEVID, sizeof(c4pub), c4pub,
                sizeof(c4priv), c4priv, sizeof(c4base), c4base);

        (void)wc_CryptoCb_Curve448MakePub(WB_DEVID_NOCB, sizeof(c4pub),
                c4pub, sizeof(c4priv), c4priv);
        (void)wc_CryptoCb_Curve448Generic(WB_DEVID_NOCB, sizeof(c4pub),
                c4pub, sizeof(c4priv), c4priv, sizeof(c4base), c4base);

        (void)wc_CryptoCb_Curve448MakePub(WB_DEVID_NONE, sizeof(c4pub),
                c4pub, sizeof(c4priv), c4priv);
        (void)wc_CryptoCb_Curve448Generic(WB_DEVID_NONE, sizeof(c4pub),
                c4pub, sizeof(c4priv), c4priv, sizeof(c4base), c4base);

        /* No device selected, free slots remain. */
        (void)wc_CryptoCb_Curve448MakePub(INVALID_DEVID, sizeof(c4pub),
                c4pub, sizeof(c4priv), c4priv);
        (void)wc_CryptoCb_Curve448Generic(INVALID_DEVID, sizeof(c4pub),
                c4pub, sizeof(c4priv), c4priv, sizeof(c4base), c4base);

        /* No device selected and no free slot left to land on. */
        wc_CryptoCb_Init();
        for (slot = 0; slot < MAX_CRYPTO_DEVID_CALLBACKS; slot++) {
            if (wc_CryptoCb_RegisterDevice(WB_DEVID_FILL + slot, wb_cb,
                    NULL) != 0)
                wb_fail = 1;
        }
        (void)wc_CryptoCb_Curve448MakePub(INVALID_DEVID, sizeof(c4pub),
                c4pub, sizeof(c4priv), c4priv);
        (void)wc_CryptoCb_Curve448Generic(INVALID_DEVID, sizeof(c4pub),
                c4pub, sizeof(c4priv), c4priv, sizeof(c4base), c4base);

        WB_NOTE("Curve448MakePub/Generic: arg guards, "
                "(dev==NULL||dev->cb==NULL)&&(devId==INVALID_DEVID) and "
                "dev&&dev->cb driven");

        /* Leave the table the way the tail of this file expects it. */
        wc_CryptoCb_Init();
        if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
            wb_fail = 1;
    }
#else
    WB_NOTE("HAVE_CURVE448 not defined; Curve448MakePub/Generic skipped");
#endif

    /* ---- wc_CryptoCb_GetFreeDevice: `devId == INVALID_DEVID &&
     * cb == NULL` (cryptocb.c :409) ----
     * See the "fourth pass" note in the file header: the (T,F) half of the
     * pair is planted directly, since it only exists transiently inside a
     * WOLF_CRYPTO_CB_CMD register command. */
    {
        int slot;

        /* (T,F): slot 0 half filled. A registration must skip it, land in
         * a later slot, and leave the half filled slot untouched. */
        wc_CryptoCb_Init();
        gCryptoDev[0].cb = wb_cb;
        if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
            wb_fail = 1;
        if (wc_CryptoCb_GetDevice(WB_DEVID) == &gCryptoDev[0])
            wb_fail = 1;
        if (gCryptoDev[0].devId != INVALID_DEVID || gCryptoDev[0].cb != wb_cb)
            wb_fail = 1;

        /* With every other slot registered, the scan must reject the half
         * filled slot rather than hand it out: no free slot, BUFFER_E. */
        for (slot = 0; slot < MAX_CRYPTO_DEVID_CALLBACKS; slot++) {
            (void)wc_CryptoCb_RegisterDevice(WB_DEVID_FILL + slot, wb_cb,
                NULL);
        }
        if (wc_CryptoCb_RegisterDevice(WB_DEVID_NOCB, NULL, NULL) !=
                WC_NO_ERR_TRACE(BUFFER_E))
            wb_fail = 1;
        if (gCryptoDev[0].devId != INVALID_DEVID || gCryptoDev[0].cb != wb_cb)
            wb_fail = 1;
        WB_NOTE("GetFreeDevice: devId==INVALID_DEVID&&cb==NULL [:409] "
                "(T,F) half filled slot skipped, full-table BUFFER_E");

        /* Leave the table the way the rest of this file expects it. */
        wc_CryptoCb_Init();
        if (wc_CryptoCb_RegisterDevice(WB_DEVID, wb_cb, NULL) != 0)
            wb_fail = 1;
    }

    wc_CryptoCb_UnRegisterDevice(WB_DEVID);
    wc_CryptoCb_UnRegisterDevice(WB_DEVID_NOCB);
    wc_CryptoCb_UnRegisterDevice(WB_DEVID_HASH_OK);

    (void)res;
    (void)intSize;
    (void)devId;
#ifdef WOLF_CRYPTO_CB_FIND
    /* Keep wb_find_cb referenced even in a variant without HAVE_CURVE25519,
     * where the only call site above is preprocessed away. */
    (void)wb_find_cb;
#endif

    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
#else
    printf("  WOLF_CRYPTO_CB not defined; nothing to exercise\n");
#endif /* WOLF_CRYPTO_CB */
    (void)wb_fail;
    return 0;
}
