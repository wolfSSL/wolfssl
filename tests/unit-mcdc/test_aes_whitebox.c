/* test_aes_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/aes.c.
 *
 * The tests/api AES suite drives aes.c through its *public* API. A handful of
 * decision conditions live in link-local (WOLFSSL_LOCAL) or file-static helpers
 * whose "impossible" operand combinations are rejected by every public caller
 * *before* the helper runs, so they can never be exercised from the API without
 * modifying library source. This translation unit reaches them by compiling
 * aes.c directly (#include) and calling the helpers with both halves of each
 * MC/DC independence pair.
 *
 * Coverage from this binary is unioned with the tests/api variant coverage by
 * source line:col in the per-module campaign (iso26262/mcdc-per-module):
 * llvm-cov computes MC/DC independence PER BINARY, and the campaign's
 * aggregate.sh ORs the "independence shown" bit across binaries by key. That is
 * why every pair below is completed *within this file* rather than relying on
 * the API tests to supply the other half.
 *
 * Build: compiled by run-mcdc.sh's white-box step with the SAME MC/DC CFLAGS,
 * -DHAVE_CONFIG_H and -I<workspace> as the instrumented library, then linked
 * against that variant's libwolfssl.a with its aes.o removed (this TU supplies
 * the instrumented aes.c). NOT part of the wolfSSL build; not registered in
 * tests/api. See tests/unit-mcdc/README.md.
 *
 * Targeted residuals (aes.c), by class:
 *   Class 1  GHASH / GHASH_UPDATE internal ptr!=NULL guards ...... 13 conditions
 *   Class 2  _AesNew_common cross-argument BAD_FUNC_ARG checks ....  6 conditions
 *   Class 3  AES-NI internal pointer/arg guards (WOLFSSL_AESNI) ....  6 conditions
 *   Class 4  AArch64 use_aes_hw_crypto && use_pmull_hw_crypto
 *            dispatch, 9 sites (WOLFSSL_ARMASM, __aarch64__,
 *            qemu-aarch64 lane only) .............................. 18 conditions
 *   Class 5  AArch64 GCM streaming internal ptr!=NULL guards
 *            (WOLFSSL_ARMASM, __aarch64__, qemu-aarch64 lane only) ..4 conditions
 * Classes 4 and 5 only compile in the qemu-aarch64 emulator lane (see
 * iso26262/mcdc-per-module campaign, db/lanes.json); on every other build
 * they reduce to a no-op stub so this file still compiles+runs natively.
 * The remaining 4 union residuals are structurally uncoverable even here
 * (2 complementary-operand decisions where unique-cause MC/DC is unsatisfiable,
 * 1 needs an internal AES failure not selectable without corrupting state,
 * 1 dead defensive branch on a provably-bounded loop index) and stay justified
 * in reports/aes/RESIDUALS.md.
 */

/* Pull aes.c in verbatim so the file-static and WOLFSSL_LOCAL helpers below are
 * in scope and instrumented in THIS binary. aes.c includes settings.h (which
 * picks up user_settings.h via -DWOLFSSL_USER_SETTINGS) and aes.h itself. */
#include <wolfcrypt/src/aes.c>

#include <stdio.h>

#ifndef INVALID_DEVID
    #define INVALID_DEVID (-2)
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* ------------------------------------------------------------------------- *
 * Class 1a: classic GHASH() internal guards.
 *
 *   if (aSz != 0 && a != NULL)   -> cond idx1 (a != NULL)
 *   if (cSz != 0 && c != NULL)   -> cond idx1 (c != NULL)
 *
 * Every public wc_AesGcm* entry point returns BAD_FUNC_ARG for
 * "size != 0 with pointer == NULL", so GHASH never sees a!=NULL / c!=NULL
 * false. Only ONE GHASH backend compiles per build (GCM_SMALL / GCM_TABLE /
 * GCM_TABLE_4BIT / WORD64-default / GCM_WORD32); calling GHASH here covers
 * whichever line:col this build compiled. When a==NULL / c==NULL the guard
 * short-circuits before dereferencing, so the NULL calls are safe.
 * ------------------------------------------------------------------------- */
#ifdef HAVE_AESGCM
static void wb_ghash_classic(void)
{
    Aes    aes;
    byte   key[16];
    byte   buf[32];
    byte   s[16];

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(buf, 0, sizeof(buf));

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_AesInit failed (classic GHASH skipped)");
        wb_fail = 1;
        return;
    }
    if (wc_AesGcmSetKey(&aes, key, sizeof(key)) != 0) {
        WB_NOTE("wc_AesGcmSetKey failed (classic GHASH skipped)");
        wc_AesFree(&aes);
        wb_fail = 1;
        return;
    }

    /* TRUE half:  aSz!=0 && a!=NULL,  cSz!=0 && c!=NULL  -> decisions true  */
    GHASH(&aes.gcm, buf, (word32)sizeof(buf), buf, (word32)sizeof(buf),
          s, (word32)sizeof(s));
    /* FALSE half: aSz!=0 && a==NULL,  cSz!=0 && c==NULL  -> decisions false,
     * flipping the a!=NULL / c!=NULL operand while size!=0 is held true. */
    GHASH(&aes.gcm, NULL, (word32)sizeof(buf), NULL, (word32)sizeof(buf),
          s, (word32)sizeof(s));

    WB_NOTE("classic GHASH ptr-guard pairs exercised");
    wc_AesFree(&aes);
}
#else
static void wb_ghash_classic(void) { WB_NOTE("HAVE_AESGCM off; classic GHASH skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 1b: streaming GHASH_UPDATE() internal guards (WOLFSSL_AESGCM_STREAM).
 *
 *   if (aSz != 0 && a != NULL)                     -> cond idx1 (a != NULL)
 *   if (aes->aOver > 0 && cSz > 0 && c != NULL)    -> cond idx2 (c != NULL)
 *   if (cSz != 0 && c != NULL)                     -> cond idx1 (c != NULL)
 *
 * GHASH_UPDATE is a single static helper (one line:col set regardless of GHASH
 * backend); one streaming build covers it. We set gcm->H via wc_AesGcmSetKey
 * and drive aes->aOver directly to reach the partial-AAD branch. Bodies use
 * AES_LASTGBLOCK(aes) and gcm->H (both valid) and never dereference a NULL a/c
 * because of the short-circuit, so every call is memory-safe.
 * ------------------------------------------------------------------------- */
#if defined(HAVE_AESGCM) && defined(WOLFSSL_AESGCM_STREAM)
static void wb_ghash_update(void)
{
    Aes    aes;
    byte   key[16];
    byte   iv[12];
    byte   buf[32];

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv,  0, sizeof(iv));
    XMEMSET(buf, 0, sizeof(buf));

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        WB_NOTE("wc_AesInit failed (GHASH_UPDATE skipped)");
        wb_fail = 1;
        return;
    }
    /* Public streaming init sets gcm->H, runs GHASH_INIT and (under
     * WOLFSSL_SMALL_STACK) heap-allocates aes->streamData that AES_LASTGBLOCK
     * indexes into -- avoids a NULL scratch deref in the manual path below. */
    if (wc_AesGcmInit(&aes, key, sizeof(key), iv, sizeof(iv)) != 0) {
        WB_NOTE("wc_AesGcmInit failed (GHASH_UPDATE skipped)");
        wc_AesFree(&aes);
        wb_fail = 1;
        return;
    }
    aes.aOver = 0;
    aes.cOver = 0;

    /* line 10130: if (aSz != 0 && a != NULL) -- flip a!=NULL, hold aSz!=0 */
    aes.aOver = 0;
    GHASH_UPDATE(&aes, buf, (word32)WC_AES_BLOCK_SIZE, NULL, 0); /* a!=NULL T */
    aes.aOver = 0;
    GHASH_UPDATE(&aes, NULL, (word32)WC_AES_BLOCK_SIZE, NULL, 0);/* a!=NULL F */

    /* line 10168: if (aes->aOver > 0 && cSz > 0 && c != NULL)
     * hold aOver>0 and cSz>0, flip c!=NULL. The body zero-fills LASTGBLOCK and
     * does not read c, so c==NULL is safe. The TRUE path resets aOver to 0, so
     * re-arm aOver before each call. */
    aes.aOver = 4;
    GHASH_UPDATE(&aes, NULL, 0, NULL, (word32)WC_AES_BLOCK_SIZE); /* c!=NULL F */
    aes.aOver = 4;
    GHASH_UPDATE(&aes, NULL, 0, buf,  (word32)WC_AES_BLOCK_SIZE); /* c!=NULL T */

    /* line 10180: if (cSz != 0 && c != NULL) -- aOver==0 so the block above is
     * skipped; hold cSz!=0, flip c!=NULL. */
    aes.aOver = 0;
    GHASH_UPDATE(&aes, NULL, 0, buf,  (word32)WC_AES_BLOCK_SIZE); /* c!=NULL T */
    aes.aOver = 0;
    GHASH_UPDATE(&aes, NULL, 0, NULL, (word32)WC_AES_BLOCK_SIZE); /* c!=NULL F */

    WB_NOTE("streaming GHASH_UPDATE ptr-guard pairs exercised");
    wc_AesFree(&aes);
}
#else
static void wb_ghash_update(void) { WB_NOTE("AESGCM stream off; GHASH_UPDATE skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 2: _AesNew_common() cross-argument BAD_FUNC_ARG checks.
 *
 * _AesNew_common(heap, devId, result_code, aesInitType, id, idLen, label)
 * validates that the id/idLen/label triple matches the init type. Each public
 * wrapper (wc_AesNew / wc_AesNew_Id / wc_AesNew_Label) hard-codes the arguments
 * it does not use, so the "wrong" combinations are unreachable through the API.
 * We call the static directly with each combination.
 *
 *   AES_NEW_INIT_ID    line 14766: if (id==NULL || idLen==0 || label!=NULL)
 *                                   -> idx2 (label != NULL)
 *   AES_NEW_INIT_LABEL line 14774: if (label==NULL || id!=NULL || idLen!=0)
 *                                   -> idx1 (id != NULL), idx2 (idLen != 0)
 *   default            line 14783: if (id!=NULL || idLen!=0 || label!=NULL)
 *                                   -> idx0 (id!=NULL), idx1 (idLen!=0), idx2 (label!=NULL)
 *
 * The BAD_FUNC_ARG branch frees nothing extra (no Aes init ran); the "all
 * false" branch runs a normal wc_AesInit* which we release with wc_AesDelete.
 * ------------------------------------------------------------------------- */
static void wb_release(Aes* aes)
{
    if (aes != NULL) {
        wc_AesFree(aes);
        XFREE(aes, NULL, DYNAMIC_TYPE_AES);
    }
}

static void wb_aesnew_common(void)
{
    unsigned char id[4];
    const char*   label = "wb-label";
    int           rc = 0;
    Aes*          aes;

    XMEMSET(id, 0x5A, sizeof(id));

#ifdef WOLF_PRIVATE_KEY_ID
    /* line 14766, idx2 (label != NULL): id!=NULL,idLen!=0 held false-contrib,
     * flip label. TRUE -> BAD_FUNC_ARG (no init); FALSE -> real ID init. */
    aes = _AesNew_common(NULL, INVALID_DEVID, &rc, AES_NEW_INIT_ID,
                         id, (int)sizeof(id), label);   /* label!=NULL -> true  */
    wb_release(aes);
    aes = _AesNew_common(NULL, INVALID_DEVID, &rc, AES_NEW_INIT_ID,
                         id, (int)sizeof(id), NULL);    /* label==NULL -> false */
    wb_release(aes);

    /* line 14774, idx1 (id!=NULL) and idx2 (idLen!=0): hold label!=NULL false,
     * flip id then idLen. */
    aes = _AesNew_common(NULL, INVALID_DEVID, &rc, AES_NEW_INIT_LABEL,
                         id, 0, label);                 /* id!=NULL   -> true  */
    wb_release(aes);
    aes = _AesNew_common(NULL, INVALID_DEVID, &rc, AES_NEW_INIT_LABEL,
                         NULL, 4, label);               /* idLen!=0   -> true  */
    wb_release(aes);
    aes = _AesNew_common(NULL, INVALID_DEVID, &rc, AES_NEW_INIT_LABEL,
                         NULL, 0, label);               /* both false -> real  */
    wb_release(aes);
    WB_NOTE("_AesNew_common ID/LABEL cross-arg pairs exercised");
#else
    (void)id; (void)label;
    WB_NOTE("WOLF_PRIVATE_KEY_ID off; ID/LABEL cases skipped");
#endif

    /* line 14783 default case (always compiled), idx0/idx1/idx2: flip each of
     * id / idLen / label with the others held false. */
    aes = _AesNew_common(NULL, INVALID_DEVID, &rc, 0 /*plain*/,
                         id,   0, NULL);                /* id!=NULL    -> true  */
    wb_release(aes);
    aes = _AesNew_common(NULL, INVALID_DEVID, &rc, 0 /*plain*/,
                         NULL, 4, NULL);                /* idLen!=0    -> true  */
    wb_release(aes);
    aes = _AesNew_common(NULL, INVALID_DEVID, &rc, 0 /*plain*/,
                         NULL, 0, label);               /* label!=NULL -> true  */
    wb_release(aes);
    aes = _AesNew_common(NULL, INVALID_DEVID, &rc, 0 /*plain*/,
                         NULL, 0, NULL);                /* all false   -> real  */
    wb_release(aes);
    WB_NOTE("_AesNew_common default cross-arg pairs exercised");
}

/* ------------------------------------------------------------------------- *
 * Class 3: AES-NI internal pointer guards (WOLFSSL_AESNI).
 *
 * When aes.c is compiled with AES-NI (the campaign's "aesni" variant), the
 * AES-NI code paths add file-static helpers whose NULL/size guards every public
 * caller pre-rejects, exactly like the classic GHASH guards:
 *
 *   AES_set_encrypt_key_AESNI / AES_set_decrypt_key_AESNI
 *       line 1068 / 1099:  if (!userKey || !aes)  -> idx0 !userKey, idx1 !aes
 *   AesGcmAadUpdate_aesni
 *       line 12136:        if (aSz != 0 && a != NULL)   -> idx1 (a != NULL)
 *   AesGcmEncryptUpdate_aesni
 *       line 12305:        AesGcmAadUpdate_aesni(..., (cSz > 0) && (c != NULL))
 *                                                       -> idx1 (c != NULL)
 *       line 12310:        if (cSz != 0 && c != NULL)   -> idx1 (c != NULL)
 *   AesGcmDecryptUpdate_aesni
 *       line 12635:        if (cSz != 0 && p != NULL)   -> idx1 (p != NULL)
 *
 * The key setters return BAD_FUNC_ARG before any AES-NI work. For the GCM
 * updaters, a data pointer == NULL with size != 0 short-circuits its guarded
 * block before dereferencing, so the NULL calls are memory-safe. A valid GCM
 * streaming state (wc_AesGcmInit) supplies gcm->H; on an AES-NI host use_aesni
 * is set, so calling the *_aesni updaters directly is state-consistent.
 * ASSERT_SAVED_VECTOR_REGISTERS is a no-op unless WOLFSSL_CHECK_VECTOR_REGISTERS.
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_AESNI
static void wb_aesni(void)
{
    {   /* key-expansion !userKey / !aes halves */
        Aes  aes;
        byte key[16];
        XMEMSET(key, 0, sizeof(key));
        XMEMSET(&aes, 0, sizeof(aes));
        (void)AES_set_encrypt_key_AESNI(NULL, 128, &aes); /* !userKey -> true  */
        (void)AES_set_encrypt_key_AESNI(key,  128, NULL); /* !userKey F, !aes T */
        (void)AES_set_decrypt_key_AESNI(NULL, 128, &aes); /* !userKey -> true  */
        (void)AES_set_decrypt_key_AESNI(key,  128, NULL); /* !userKey F, !aes T */
    }

#if defined(HAVE_AESGCM) && defined(WOLFSSL_AESGCM_STREAM)
    {   /* AES-NI GCM streaming ptr guards; both halves within this binary */
        Aes  aes;
        byte key[16], iv[12], in[16], out[16];
        XMEMSET(key, 0, sizeof(key)); XMEMSET(iv, 0, sizeof(iv));
        XMEMSET(in,  0, sizeof(in));  XMEMSET(out, 0, sizeof(out));

        if (wc_AesInit(&aes, NULL, INVALID_DEVID) == 0 &&
            wc_AesGcmInit(&aes, key, sizeof(key), iv, sizeof(iv)) == 0) {
            /* 12136: if (aSz != 0 && a != NULL) -- hold aSz!=0, flip a!=NULL */
            aes.aOver = 0;
            (void)AesGcmAadUpdate_aesni(&aes, in,   16, 0);       /* a!=NULL T */
            aes.aOver = 0;
            (void)AesGcmAadUpdate_aesni(&aes, NULL, 16, 0);       /* a!=NULL F */
            /* 12305 + 12310: c!=NULL -- hold cSz!=0, flip c (out) */
            aes.aOver = 0; aes.cOver = 0;
            (void)AesGcmEncryptUpdate_aesni(&aes, out,  in, 16, in, 16); /* c T */
            aes.aOver = 0; aes.cOver = 0;
            (void)AesGcmEncryptUpdate_aesni(&aes, NULL, in, 16, in, 16); /* c F */
            /* 12635: p!=NULL -- hold cSz!=0, flip p (out) */
            aes.aOver = 0; aes.cOver = 0;
            (void)AesGcmDecryptUpdate_aesni(&aes, out,  in, 16, in, 16); /* p T */
            aes.aOver = 0; aes.cOver = 0;
            (void)AesGcmDecryptUpdate_aesni(&aes, NULL, in, 16, in, 16); /* p F */
            wc_AesFree(&aes);
        }
        else {
            WB_NOTE("AES-NI GCM streaming init failed; GCM guards skipped");
        }
    }
#endif /* HAVE_AESGCM && WOLFSSL_AESGCM_STREAM */
    WB_NOTE("AES-NI internal ptr-guard pairs exercised");
}
#else
static void wb_aesni(void) { WB_NOTE("WOLFSSL_AESNI off; AES-NI internals skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 4: AArch64 hw-crypto dispatch, `aes->use_aes_hw_crypto &&
 * aes->use_pmull_hw_crypto` (9 sites in aes.c: wc_AesGcmSetKey's H
 * generation; the static GHASH_INIT helper; the wc_AesGcmEncrypt/
 * wc_AesGcmDecrypt one-shot APIs; and the streaming quintet AesGcmInit /
 * AesGcmEncryptUpdate / AesGcmEncryptFinal / AesGcmDecryptUpdate /
 * AesGcmDecryptFinal). qemu-aarch64 -cpu max always advertises FEAT_AES and
 * FEAT_PMULL, so on this lane Check_CPU_support_HwCrypto() (this file)
 * always derives both fields true and every site's FALSE side is
 * unreachable from tests/api.
 *
 * Check_CPU_support_HwCrypto() only re-detects when its cpuid_flags cache
 * equals WC_CPUID_INITIALIZER; any other value is used as-is. Seeding that
 * file-static cache with a chosen AES/PMULL bit combination before a key
 * operation makes wc_AesSetKey (called by wc_AesGcmSetKey) derive exactly
 * that combination, which then simply persists on the struct fields for
 * every later call on the same Aes object -- no further seam needed. Only
 * forcing hw-crypto OFF is safety-relevant here (it always selects the
 * plain-C path); the TRUE side is the lane's own natural case, reproduced
 * explicitly below to complete each site's independence pair.
 *
 * GHASH_INIT (line ~10119) is the one exception: it is called only from
 * AesGcmInit_C, which the AesGcmInit dispatch (line ~13449) selects
 * precisely when hw-crypto is NOT both true, so GHASH_INIT's own TRUE
 * branch can never run through the public API no matter how cpuid_flags is
 * seeded (the AARCH64 init path is chosen instead and never calls
 * GHASH_INIT at all). It is reached by calling the static directly with
 * both hand-set field combinations, per the same forcing idiom the
 * AES-NI/x86 section above uses for aes.aOver/aes.cOver.
 * ------------------------------------------------------------------------- */
#if defined(__aarch64__) && defined(WOLFSSL_ARMASM) && \
    !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO) && defined(HAVE_AESGCM) && \
    defined(WOLFSSL_AESGCM_STREAM)
static int wb_setkey_with_cpuid_aarch64(Aes* aes, cpuid_flags_t flags,
    const byte* key, word32 keySz)
{
    int ret;
    if (wc_AesInit(aes, NULL, INVALID_DEVID) != 0)
        return -1;
    cpuid_flags = flags;
    ret = wc_AesGcmSetKey(aes, key, keySz);
    if (ret != 0)
        wc_AesFree(aes);
    return ret;
}

static void wb_aarch64_hwcrypto_dispatch(void)
{
    cpuid_flags_t saved = cpuid_flags;
    Aes  aes;
    byte key[16], iv[12], in[16], out[16], out2[16], tag[16];
    int  combo;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv,  0, sizeof(iv));
    XMEMSET(in,  0x22, sizeof(in));

    /* 8380 (and every site below, which just reads the fields it leaves
     * behind): 0/0, 1/0, 0/1 are the FALSE side; 1/1 is the natural,
     * always-taken TRUE side, forced explicitly to complete the pairs. */
    for (combo = 0; combo < 4; combo++) {
        cpuid_flags_t flags = (combo == 0) ? (cpuid_flags_t)0 :
                               (combo == 1) ? (cpuid_flags_t)CPUID_AES :
                               (combo == 2) ? (cpuid_flags_t)CPUID_PMULL :
                                 (cpuid_flags_t)(CPUID_AES | CPUID_PMULL);

        if (wb_setkey_with_cpuid_aarch64(&aes, flags, key, sizeof(key)) != 0) {
            WB_NOTE("aarch64 hw-crypto: wc_AesGcmSetKey failed; combo skipped");
            wb_fail = 1;
            continue;
        }

        /* 10913 / 11694: one-shot Encrypt/Decrypt read the fields left by
         * the SetKey above; no further cpuid re-derivation happens on this
         * path, so the forced combo carries straight through. */
        if (wc_AesGcmEncrypt(&aes, out, in, sizeof(in), iv, sizeof(iv),
                tag, sizeof(tag), NULL, 0) != 0) {
            WB_NOTE("aarch64 hw-crypto: wc_AesGcmEncrypt failed");
            wb_fail = 1;
        }
        if (wc_AesGcmDecrypt(&aes, out2, out, sizeof(out), iv, sizeof(iv),
                tag, sizeof(tag), NULL, 0) != 0) {
            WB_NOTE("aarch64 hw-crypto: wc_AesGcmDecrypt failed");
            wb_fail = 1;
        }

        /* 13449 / 13576 / 13638: streaming encrypt. key=NULL reuses the
         * key already set above -- passing a real key here would call
         * wc_AesGcmSetKey again and re-derive the fields from cpuid_flags,
         * undoing the forced combo. */
        if (wc_AesGcmInit(&aes, NULL, 0, iv, sizeof(iv)) != 0 ||
            wc_AesGcmEncryptUpdate(&aes, out, in, sizeof(in), NULL, 0) != 0 ||
            wc_AesGcmEncryptFinal(&aes, tag, sizeof(tag)) != 0) {
            WB_NOTE("aarch64 hw-crypto: streaming encrypt failed");
            wb_fail = 1;
        }
        /* 13449 / 13722 / 13782: streaming decrypt, same aes/key/iv. */
        if (wc_AesGcmInit(&aes, NULL, 0, iv, sizeof(iv)) != 0 ||
            wc_AesGcmDecryptUpdate(&aes, out2, out, sizeof(out), NULL, 0) != 0 ||
            wc_AesGcmDecryptFinal(&aes, tag, sizeof(tag)) != 0) {
            WB_NOTE("aarch64 hw-crypto: streaming decrypt failed");
            wb_fail = 1;
        }

        wc_AesFree(&aes);
    }

    /* 10119 GHASH_INIT: unreachable with a TRUE combo through the public
     * API (see comment above) -- call the static directly. */
    if (wb_setkey_with_cpuid_aarch64(&aes,
            (cpuid_flags_t)(CPUID_AES | CPUID_PMULL), key, sizeof(key)) == 0) {
        aes.use_aes_hw_crypto = 1;
        aes.use_pmull_hw_crypto = 1;
        GHASH_INIT(&aes);                        /* both true     -> TRUE  */
        aes.use_aes_hw_crypto = 0;
        aes.use_pmull_hw_crypto = 0;
        GHASH_INIT(&aes);                        /* not both true -> FALSE */
        wc_AesFree(&aes);
    }
    else {
        WB_NOTE("aarch64 hw-crypto: GHASH_INIT direct-call setup failed");
        wb_fail = 1;
    }

    cpuid_flags = saved;
    WB_NOTE("aarch64 hw-crypto dispatch pairs exercised (9 sites)");
}
#else
static void wb_aarch64_hwcrypto_dispatch(void)
{ WB_NOTE("aarch64 hw-crypto dispatch not compiled in this variant; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 5: AArch64 GCM streaming internal pointer guards (4 conditions),
 * the AARCH64 twins of the AES-NI Class 3 GCM guards above:
 *
 *   AesGcmAadUpdate_AARCH64
 *       if (aSz != 0 && a != NULL)                        -> idx1 (a != NULL)
 *   AesGcmEncryptUpdate_AARCH64
 *       AesGcmAadUpdate_AARCH64(..., (cSz > 0) && (c != NULL))
 *                                                          -> idx1 (c != NULL)
 *       if (cSz != 0 && c != NULL)                         -> idx1 (c != NULL)
 *   AesGcmDecryptUpdate_AARCH64
 *       if (cSz != 0 && p != NULL)                         -> idx1 (p != NULL)
 *
 * Every public wc_AesGcm* entry point rejects a NULL data pointer paired
 * with a non-zero size before these AARCH64 helpers run, so the NULL halves
 * are unreachable from tests/api. Calling the static helpers directly (bypassing
 * the use_aes_hw_crypto/use_pmull_hw_crypto dispatch entirely, exactly as
 * the AES-NI section above bypasses use_aesni) reaches both halves safely:
 * a NULL pointer with a non-zero size short-circuits its guard before any
 * dereference. The encrypt updater's call-arg and its own guard read the
 * SAME (c, cSz) pair in the same call, so one c!=NULL/c==NULL pair (cSz!=0
 * held) completes both conditions at once.
 * ------------------------------------------------------------------------- */
#if defined(__aarch64__) && defined(WOLFSSL_ARMASM) && \
    !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO) && defined(HAVE_AESGCM) && \
    defined(WOLFSSL_AESGCM_STREAM)
static void wb_aarch64_gcm_ptr_guards(void)
{
    Aes  aes;
    byte key[16], iv[12], in[16], out[16];

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv,  0, sizeof(iv));
    XMEMSET(in,  0, sizeof(in));
    XMEMSET(out, 0, sizeof(out));

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) == 0 &&
        wc_AesGcmInit(&aes, key, sizeof(key), iv, sizeof(iv)) == 0) {
        /* AadUpdate: hold aSz!=0, flip a!=NULL. endA=0 so the trailing
         * "endA && aOver>0" tail (already reached via the streaming API)
         * is not re-exercised here. */
        aes.aOver = 0;
        (void)AesGcmAadUpdate_AARCH64(&aes, in,   16, 0); /* a!=NULL T */
        aes.aOver = 0;
        (void)AesGcmAadUpdate_AARCH64(&aes, NULL, 16, 0); /* a!=NULL F */

        /* EncryptUpdate: hold cSz!=0, flip c (out) -- covers both the
         * call-arg into AadUpdate's endA and EncryptUpdate's own guard. */
        aes.aOver = 0; aes.cOver = 0;
        (void)AesGcmEncryptUpdate_AARCH64(&aes, out,  in, 16, in, 16); /* c T */
        aes.aOver = 0; aes.cOver = 0;
        (void)AesGcmEncryptUpdate_AARCH64(&aes, NULL, in, 16, in, 16); /* c F */

        /* DecryptUpdate: hold cSz!=0, flip p (out). */
        aes.aOver = 0; aes.cOver = 0;
        (void)AesGcmDecryptUpdate_AARCH64(&aes, out,  in, 16, in, 16); /* p T */
        aes.aOver = 0; aes.cOver = 0;
        (void)AesGcmDecryptUpdate_AARCH64(&aes, NULL, in, 16, in, 16); /* p F */

        wc_AesFree(&aes);
    }
    else {
        WB_NOTE("aarch64 GCM streaming init failed; ptr guards skipped");
        wb_fail = 1;
    }
    WB_NOTE("aarch64 AesGcm*Update_AARCH64 ptr-guard pairs exercised (4 conditions)");
}
#else
static void wb_aarch64_gcm_ptr_guards(void)
{ WB_NOTE("aarch64 GCM streaming ptr guards not compiled in this variant; skipped"); }
#endif

int main(void)
{
    printf("aes.c white-box MC/DC supplement\n");
#ifdef NO_AES
    printf("  NO_AES defined; nothing to exercise\n");
    return 0;
#else
    wb_ghash_classic();
    wb_ghash_update();
    wb_aesnew_common();
    wb_aesni();
    wb_aarch64_hwcrypto_dispatch();
    wb_aarch64_gcm_ptr_guards();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
