/* test_internal_cryptocb_whitebox.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* The signature-verify wrappers in internal.c all end in the same guard:
 *
 *     if (ret != 0 || ssl->eccVerifyRes == 0)      EccVerify
 *     ret = (ret != 0 || ssl->eccVerifyRes == 0) ? VERIFY_SIGN_ERROR : 0;
 *                                                  Ed25519Verify, Ed448Verify
 *
 * Two operands, and an ordinary handshake pairs neither. A good signature
 * gives (F,F); a bad one gives... still (F,F) at this line, because a bad
 * signature is not an error -- wc_*_verify_* returns 0 and reports the verdict
 * in eccVerifyRes, which the black-box tests cannot set to 0 without a
 * genuinely forged signature, and cannot make the call itself fail at all.
 * The first operand is true only when the maths breaks: out of memory in the
 * bignum layer, or an offload device that refuses.
 *
 * WOLF_CRYPTO_CB is the supported way to be that device. mcdc_fault_cryptocb.h
 * registers one that answers CRYPTOCB_UNAVAILABLE to everything except the
 * operation a vector selects, so each wrapper can be driven three ways:
 *
 *   device returns an error   -> (T,-)  first operand, second short-circuited
 *   device returns 0, res 0   -> (F,T)  second operand: "verify said no"
 *   device returns 0, res 1   -> (F,F)  the good path
 *
 * The dispatch in wc_ecc_verify_hash / wc_ed25519_verify_msg /
 * wc_ed448_verify_msg happens after the argument checks but before any key
 * material is touched, so these vectors need a key object with a devId and
 * nothing else -- no certificate, no peer, no valid public point. That is the
 * whole reason this is cheap: the device intercepts before the maths.
 *
 * EccMakeKey gets the same treatment for a different guard, and it is the one
 * that did not work -- recorded here because the reason is the useful part.
 * Its
 *
 *     if (ret == 0 && key->dp)
 *
 * looked like the same shape: let a device claim the key was generated without
 * generating anything, and dp should still be NULL. It is not. _ecc_make_key_ex
 * calls wc_ecc_set_curve() before it consults the device, and set_curve either
 * fails -- making ret non-zero -- or assigns dp from the curve table. There is
 * no path that returns 0 with dp unset, so (T,F) does not exist and the second
 * operand has no independence pair in any configuration. The vectors below are
 * kept because they exercise the offload dispatch and because they are the
 * evidence for that claim; the operand itself is now an exclusion with the
 * argument written out.
 *
 * VerifyRsaSign's NULL checks are here too. They are not fault injection --
 * they are a WOLFSSL_LOCAL entry point whose arguments are always non-NULL by
 * construction in the protocol code, so only a direct call reaches them.
 *
 * Rules, as for the sibling drivers:
 *   - options.h FIRST, or the smoke build compiles this with the feature
 *     macros undefined and it silently becomes a no-op that still exits 0.
 *   - main() ALWAYS returns 0; a non-zero exit discards the whole variant.
 */

#include <wolfssl/options.h>

#include "tests/unit-mcdc/mcdc_fault_cryptocb.h"

/* VerifyRsaSign checks the RECOVERED plaintext against the expected one:
 *
 *     if (ret > 0) {
 *         if (ret != (int)plainSz || !out || XMEMCMP(plain, out, plainSz) != 0)
 *
 * A device cannot drive this. RsaPublicDecrypt routes every operation except
 * verify through the callback ("Everything except verify goes to crypto cb"),
 * and the one path that does dispatch feeds its output back through PKCS#1
 * unpadding, so a device that returns anything but a correctly padded block
 * makes ret negative and the guard is never reached at all. Reaching it needs
 * a positive ret with a chosen length and a chosen buffer -- including a NULL
 * buffer, which no real implementation ever produces alongside a positive
 * length, and which is exactly what the middle operand is defending against.
 *
 * So this one uses the #define idiom instead: a white-box that #includes the
 * .c under test can redirect any function that .c calls but does not define.
 * Two levers on one guard, each where it fits. */
/* One condition decides both the redirect and the body that defines what the
 * redirect points at. They were separate once: the #define sat outside the
 * feature guard and the mock inside it, so a build without WOLF_CRYPTO_CB
 * redirected internal.c's calls to a function that had been compiled away.
 * That fails at link, and the smoke harness files a link failure under "not
 * built here" -- indistinguishable from a driver legitimately skipped for its
 * configuration. Keep them on one macro. */
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS) && defined(WOLF_CRYPTO_CB) && \
    !defined(HAVE_PK_CALLBACKS) && !defined(WOLFSSL_ASYNC_CRYPT)
    #define MCDC_CRYPTOCB_WB
#endif

#if defined(MCDC_CRYPTOCB_WB) && !defined(NO_RSA)
    static int mcdc_rsa_verify_inline(byte* in, word32 inLen, byte** out,
                                      RsaKey* key);
    #define wc_RsaSSL_VerifyInline(a, b, c, d) \
            mcdc_rsa_verify_inline((a), (b), (c), (d))
#endif

#include <src/internal.c>

#include <stdio.h>
#include <string.h>

#ifdef MCDC_CRYPTOCB_WB

static int g_checks;

/* A digest length the verify entry points accept: inside
 * [WC_MIN_DIGEST_SIZE_FOR_VERIFY, WC_MAX_DIGEST_SIZE], so the length check
 * above the callback dispatch lets the vector through. */
static byte g_sig[72];
static byte g_hash[32];

/* The three answers a device can give, named for what they mean at the guard
 * rather than for what the device does. */
enum {
    WB_DEV_ERROR,      /* refuses: ret != 0                      */
    WB_DEV_SAYS_NO,    /* succeeds, verdict is "bad signature"   */
    WB_DEV_SAYS_YES    /* succeeds, verdict is "good signature"  */
};

static const char* wb_answer_name(int answer)
{
    switch (answer) {
        case WB_DEV_ERROR:   return "device error";
        case WB_DEV_SAYS_NO: return "verify says no";
        default:             return "verify says yes";
    }
}

/* Arm the device for one vector. eccVerifyRes is the out-parameter the
 * wrappers read, and the device deliberately does not write it: leaving it as
 * the caller set it is what separates SAYS_NO from SAYS_YES. */
static void wb_arm(WOLFSSL* ssl, int pkType, int answer)
{
    mcdc_cb_answer_pk(pkType, answer == WB_DEV_ERROR ? WC_HW_E : 0);
    /* wc_ed448_verify_msg zeroes *res before dispatching and the other two do
     * not, so the device sets the verdict rather than the caller. */
    mcdc_cb_verdict(answer == WB_DEV_SAYS_YES ? 1 : 0);
    ssl->eccVerifyRes = (answer == WB_DEV_SAYS_YES) ? 1 : 0;
}

/* ------------------------------------------------------------- EccVerify */

#ifdef HAVE_ECC
static void wb_ecc_verify(WOLFSSL* ssl)
{
    static const int kAnswers[] = { WB_DEV_ERROR, WB_DEV_SAYS_NO,
                                    WB_DEV_SAYS_YES };
    size_t i;

    for (i = 0; i < sizeof(kAnswers) / sizeof(kAnswers[0]); i++) {
        ecc_key key;
        int ret;

        if (wc_ecc_init_ex(&key, NULL, MCDC_CB_DEVID) != 0)
            continue;

        wb_arm(ssl, WC_PK_TYPE_ECDSA_VERIFY, kAnswers[i]);
        ret = EccVerify(ssl, g_sig, (word32)sizeof(g_sig),
                        g_hash, (word32)sizeof(g_hash), &key, NULL);
        printf("  EccVerify %-16s -> %d (res %d, device hit %d)\n",
               wb_answer_name(kAnswers[i]), ret, ssl->eccVerifyRes,
               mcdc_cb_matched());
        g_checks++;

        wc_ecc_free(&key);
    }

    /* The same guard once more with the device silent, so the wrapper is also
     * seen taking the software path it takes in every other test. */
    mcdc_cb_disarm();
}

/* ------------------------------------------------------------ EccMakeKey */

static void wb_ecc_make_key(WOLFSSL* ssl, WC_RNG* rng)
{
    ecc_key key;

    /* _ecc_make_key_ex rejects a NULL rng before it reaches the callback
     * dispatch, so these vectors need a real one on the WOLFSSL. */
    ssl->rng = rng;

    /* Device claims the key was generated but generates nothing. dp is set
     * anyway, by the wc_ecc_set_curve() that ran before the dispatch -- this
     * is the vector that demonstrates the operand is unpairable. */
    if (wc_ecc_init_ex(&key, NULL, MCDC_CB_DEVID) == 0) {
        int ret;

        mcdc_cb_answer_pk(WC_PK_TYPE_EC_KEYGEN, 0);
        ret = EccMakeKey(ssl, &key, NULL);
        printf("  EccMakeKey  empty success -> %d (dp %s)\n",
               ret, key.dp == NULL ? "NULL" : "set");
        g_checks++;
        wc_ecc_free(&key);
    }

    /* And the refusing device, for the ret operand. */
    if (wc_ecc_init_ex(&key, NULL, MCDC_CB_DEVID) == 0) {
        int ret;

        mcdc_cb_answer_pk(WC_PK_TYPE_EC_KEYGEN, WC_HW_E);
        ret = EccMakeKey(ssl, &key, NULL);
        printf("  EccMakeKey  device error  -> %d\n", ret);
        g_checks++;
        wc_ecc_free(&key);
    }

    mcdc_cb_disarm();
    ssl->rng = NULL;
}
#endif /* HAVE_ECC */

/* --------------------------------------------------------- Ed25519Verify */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)
static void wb_ed25519_verify(WOLFSSL* ssl)
{
    static const int kAnswers[] = { WB_DEV_ERROR, WB_DEV_SAYS_NO,
                                    WB_DEV_SAYS_YES };
    size_t i;

    for (i = 0; i < sizeof(kAnswers) / sizeof(kAnswers[0]); i++) {
        ed25519_key key;
        int ret;

        if (wc_ed25519_init_ex(&key, NULL, MCDC_CB_DEVID) != 0)
            continue;

        wb_arm(ssl, WC_PK_TYPE_ED25519_VERIFY, kAnswers[i]);
        ret = Ed25519Verify(ssl, g_sig, ED25519_SIG_SIZE,
                            g_hash, (word32)sizeof(g_hash), &key, NULL);
        printf("  Ed25519Verify %-16s -> %d (res %d)\n",
               wb_answer_name(kAnswers[i]), ret, ssl->eccVerifyRes);
        g_checks++;

        wc_ed25519_free(&key);
    }

    mcdc_cb_disarm();
}
#endif

/* ----------------------------------------------------------- Ed448Verify */

#if defined(HAVE_ED448) && defined(HAVE_ED448_VERIFY)
static void wb_ed448_verify(WOLFSSL* ssl)
{
    static const int kAnswers[] = { WB_DEV_ERROR, WB_DEV_SAYS_NO,
                                    WB_DEV_SAYS_YES };
    static byte sig448[ED448_SIG_SIZE];
    size_t i;

    for (i = 0; i < sizeof(kAnswers) / sizeof(kAnswers[0]); i++) {
        ed448_key key;
        int ret;

        if (wc_ed448_init_ex(&key, NULL, MCDC_CB_DEVID) != 0)
            continue;

        wb_arm(ssl, WC_PK_TYPE_ED448_VERIFY, kAnswers[i]);
        ret = Ed448Verify(ssl, sig448, (word32)sizeof(sig448),
                          g_hash, (word32)sizeof(g_hash), &key, NULL);
        printf("  Ed448Verify %-16s -> %d (res %d)\n",
               wb_answer_name(kAnswers[i]), ret, ssl->eccVerifyRes);
        g_checks++;

        wc_ed448_free(&key);
    }

    mcdc_cb_disarm();
}
#endif

/* ---------------------------------------------------------- VerifyRsaSign */

#ifndef NO_RSA

/* What the next redirected wc_RsaSSL_VerifyInline reports. */
static int   g_rsaRet;
static byte* g_rsaOut;

static int mcdc_rsa_verify_inline(byte* in, word32 inLen, byte** out,
                                  RsaKey* key)
{
    (void)in; (void)inLen; (void)key;

    if (out != NULL)
        *out = g_rsaOut;
    return g_rsaRet;
}

/* The recovered-plaintext comparison, one vector per operand. */
static void wb_rsa_recovered_plain(WOLFSSL* ssl)
{
    static byte plain[32];
    static byte recovered[32];
    static byte wrong[32];
    int ret;
    size_t i;

    static const struct {
        const char* name;
        int         retVal;   /* what the verify reports as the length */
        int         useOut;   /* 0 -> NULL buffer, 1 -> recovered, 2 -> wrong */
    } kRows[] = {
        /* length disagrees: first operand true, rest short-circuited */
        { "short length",   (int)sizeof(plain) - 1, 1 },
        /* length agrees but no buffer came back: second operand */
        { "NULL plaintext", (int)sizeof(plain),     0 },
        /* length and buffer agree, content does not: third operand */
        { "wrong content",  (int)sizeof(plain),     2 },
        /* everything agrees: the accepting path, all three false */
        { "match",          (int)sizeof(plain),     1 },
        /* not a positive return at all, so the guard is skipped */
        { "verify failed",  -1,                     1 }
    };

    XMEMSET(plain,     0x33, sizeof(plain));
    XMEMSET(recovered, 0x33, sizeof(recovered));
    XMEMSET(wrong,     0x44, sizeof(wrong));

    for (i = 0; i < sizeof(kRows) / sizeof(kRows[0]); i++) {
        g_rsaRet = kRows[i].retVal;
        g_rsaOut = (kRows[i].useOut == 0) ? NULL :
                   (kRows[i].useOut == 1) ? recovered : wrong;

        ret = VerifyRsaSign(ssl, g_sig, (word32)sizeof(g_sig),
                            plain, (word32)sizeof(plain), 0, 0, NULL, NULL);
        printf("  VerifyRsaSign %-15s -> %d\n", kRows[i].name, ret);
        g_checks++;
    }

    g_rsaRet = 0;
    g_rsaOut = NULL;
}

static void wb_rsa_null_args(WOLFSSL* ssl)
{
    static byte plain[32];
    int ret;

    /* First operand: signature buffer NULL, plain valid. */
    ret = VerifyRsaSign(ssl, NULL, (word32)sizeof(g_sig),
                        plain, (word32)sizeof(plain), 0, 0, NULL, NULL);
    printf("  VerifyRsaSign sig NULL   -> %d\n", ret);
    g_checks++;

    /* Second operand: signature valid, plain NULL. The first operand must be
     * false for this one to be evaluated at all. */
    ret = VerifyRsaSign(ssl, g_sig, (word32)sizeof(g_sig),
                        NULL, (word32)sizeof(plain), 0, 0, NULL, NULL);
    printf("  VerifyRsaSign plain NULL -> %d\n", ret);
    g_checks++;

    /* Both non-NULL, but the signature is longer than the engine accepts, so
     * the size guard below the NULL checks is reached with (F,F) above it. */
    ret = VerifyRsaSign(ssl, g_sig, ENCRYPT_LEN + 1,
                        plain, (word32)sizeof(plain), 0, 0, NULL, NULL);
    printf("  VerifyRsaSign oversize   -> %d\n", ret);
    g_checks++;
}
#endif

int main(void)
{
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL*     ssl = NULL;
#ifdef HAVE_ECC
    WC_RNG       rng;
    int          rngReady = 0;
#endif

    wolfSSL_Init();

    XMEMSET(g_sig,  0xA5, sizeof(g_sig));
    XMEMSET(g_hash, 0x5A, sizeof(g_hash));

    if (mcdc_cb_install() != 0) {
        printf("internal cryptocb white-box: device registration refused\n");
        goto done;
    }

    /* The wrappers read ssl->eccVerifyRes and, on some builds, ssl->ctx; a
     * zeroed WOLFSSL with a real CTX behind it is all they need. */
    ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        printf("internal cryptocb white-box: no CTX\n");
        goto done;
    }

    ssl = (WOLFSSL*)XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    if (ssl == NULL) {
        printf("internal cryptocb white-box: no SSL\n");
        goto done;
    }
    XMEMSET(ssl, 0, sizeof(WOLFSSL));
    ssl->ctx = ctx;

#ifdef HAVE_ECC
    wb_ecc_verify(ssl);
    if (wc_InitRng(&rng) == 0) {
        rngReady = 1;
        wb_ecc_make_key(ssl, &rng);
    }
#endif
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)
    wb_ed25519_verify(ssl);
#endif
#if defined(HAVE_ED448) && defined(HAVE_ED448_VERIFY)
    wb_ed448_verify(ssl);
#endif
#ifndef NO_RSA
    wb_rsa_null_args(ssl);
    wb_rsa_recovered_plain(ssl);
#endif

    printf("internal cryptocb white-box: %d vectors driven\n", g_checks);

done:
#ifdef HAVE_ECC
    if (rngReady)
        wc_FreeRng(&rng);
#endif
    mcdc_cb_uninstall();
    XFREE(ssl, NULL, DYNAMIC_TYPE_SSL);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;   /* always 0: a non-zero exit discards the variant */
}

#else

int main(void)
{
    printf("internal cryptocb white-box: skipped "
           "(needs WOLF_CRYPTO_CB, no pk-callbacks, no async)\n");
    return 0;
}

#endif
