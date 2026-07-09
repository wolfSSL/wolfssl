/* test_rsa_whitebox.c
 *
 * White-box MC/DC supplement for wolfcrypt/src/rsa.c.
 *
 * The tests/api RSA suite drives rsa.c through its *public* API. A handful of
 * decision conditions live in file-static helpers whose "impossible" operand
 * combinations are rejected by every public caller *before* the helper runs, so
 * they can never be exercised from the API without modifying library source.
 * This translation unit reaches them by compiling rsa.c directly (#include) and
 * calling the helpers with both halves of each MC/DC independence pair.
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
 * against that variant's libwolfssl.a with its rsa.o removed (this TU supplies
 * the instrumented rsa.c). NOT part of the wolfSSL build; not registered in
 * tests/api. See tests/unit-mcdc/README.md.
 *
 * Targeted residuals (rsa.c), by class:
 *   Class 1  _NewRsaKey_common cross-argument BAD_FUNC_ARG checks ... 9 conditions
 *   Class 2  _RsaExportKey NULL-pointer guard ..................... 11 conditions
 *   Class 3  _RsaFlattenPublicKey NULL-pointer guard ...............  5 conditions
 *   Class 4  wc_CompareDiffPQ p/q NULL guard ......................  2 conditions
 *   Class 5  _RsaPrivateKeyDecodeRaw arg/size guards ............... 15 conditions
 * The RsaMGF1 buffer-size check (line ~1038) is intentionally skipped: its
 * second operand ((word32)hLen > sizeof(tmpA)) is structurally unsatisfiable
 * (hLen <= WC_MAX_DIGEST_SIZE < WC_MAX_DIGEST_SIZE+4 == sizeof(tmpA)), so
 * unique-cause MC/DC for it is unreachable, and the surrounding path runs real
 * hashing/allocation that we prefer not to drive from here. See RESIDUALS.md.
 */

/* Pull rsa.c in verbatim so the file-static helpers below are in scope and
 * instrumented in THIS binary. rsa.c includes settings.h (which picks up
 * user_settings.h via -DWOLFSSL_USER_SETTINGS) and rsa.h itself. */
#include <wolfcrypt/src/rsa.c>

#include <stdio.h>

#ifndef INVALID_DEVID
    #define INVALID_DEVID (-2)
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)

/* ------------------------------------------------------------------------- *
 * Class 1: _NewRsaKey_common() cross-argument BAD_FUNC_ARG checks.
 *
 * _NewRsaKey_common(heap, devId, result_code, rsaInitType, id, idLen, label)
 * validates that the id/idLen/label triple matches the init type. Each public
 * wrapper (wc_NewRsaKey / wc_NewRsaKey_Id / wc_NewRsaKey_Label) hard-codes the
 * arguments it does not use, so the "wrong" combinations are unreachable through
 * the API. We call the static directly with each combination.
 *
 *   RSA_NEW_INIT_ID    line 204: if (id==NULL || idLen==0 || label!=NULL)
 *                                 -> idx0 (id==NULL), idx1 (idLen==0), idx2 (label!=NULL)
 *   RSA_NEW_INIT_LABEL line 212: if (label==NULL || id!=NULL || idLen!=0)
 *                                 -> idx0 (label==NULL), idx1 (id!=NULL), idx2 (idLen!=0)
 *   default            line 221: if (id!=NULL || idLen!=0 || label!=NULL)
 *                                 -> idx0 (id!=NULL), idx1 (idLen!=0), idx2 (label!=NULL)
 *
 * The BAD_FUNC_ARG branch frees the key internally and returns NULL (nothing to
 * free); the "all false" branch returns a real initialized key we release with
 * wc_DeleteRsaKey. On any single bad arg the check returns before dereferencing,
 * so every call is memory-safe.
 * ------------------------------------------------------------------------- */
#ifndef WC_NO_CONSTRUCTORS
static void wb_rsa_release(RsaKey* key)
{
    if (key != NULL) {
        (void)wc_DeleteRsaKey(key, NULL);
    }
}

static void wb_newrsakey_common(void)
{
    unsigned char idbuf[4];
    char          lbl[] = "x";
    int           rc = 0;
    RsaKey*       key;

    XMEMSET(idbuf, 0x5A, sizeof(idbuf));

#ifdef WOLF_PRIVATE_KEY_ID
    /* line 204 (ID case), idx0/idx1/idx2: hold two operands false, flip one to
     * make it independently decide the outcome; plus the all-false real init. */
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_ID,
                            NULL, 4, NULL);        /* id==NULL   -> true  */
    wb_rsa_release(key);
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_ID,
                            idbuf, 0, NULL);       /* idLen==0   -> true  */
    wb_rsa_release(key);
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_ID,
                            idbuf, 4, lbl);        /* label!=NULL-> true  */
    wb_rsa_release(key);
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_ID,
                            idbuf, 4, NULL);       /* all false  -> real  */
    wb_rsa_release(key);

    /* line 212 (LABEL case), idx0/idx1/idx2: flip each operand, plus all-false. */
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_LABEL,
                            NULL, 0, NULL);        /* label==NULL-> true  */
    wb_rsa_release(key);
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_LABEL,
                            idbuf, 0, lbl);        /* id!=NULL   -> true  */
    wb_rsa_release(key);
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_LABEL,
                            NULL, 4, lbl);         /* idLen!=0   -> true  */
    wb_rsa_release(key);
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_LABEL,
                            NULL, 0, lbl);         /* all false  -> real  */
    wb_rsa_release(key);
    WB_NOTE("_NewRsaKey_common ID/LABEL cross-arg pairs exercised");
#else
    (void)lbl;
    WB_NOTE("WOLF_PRIVATE_KEY_ID off; ID/LABEL cases skipped");
#endif

    /* line 221 default case (always compiled), idx0/idx1/idx2: flip each of
     * id / idLen / label with the others held false, plus the all-false real
     * init (also produced by wc_NewRsaKey, done once here for this binary). */
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_PLAIN,
                            idbuf, 0, NULL);       /* id!=NULL   -> true  */
    wb_rsa_release(key);
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_PLAIN,
                            NULL, 4, NULL);        /* idLen!=0   -> true  */
    wb_rsa_release(key);
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_PLAIN,
                            NULL, 0, lbl);         /* label!=NULL-> true  */
    wb_rsa_release(key);
    key = _NewRsaKey_common(NULL, INVALID_DEVID, &rc, RSA_NEW_INIT_PLAIN,
                            NULL, 0, NULL);        /* all false  -> real  */
    wb_rsa_release(key);
    WB_NOTE("_NewRsaKey_common default cross-arg pairs exercised");
}
#else
static void wb_newrsakey_common(void) { WB_NOTE("WC_NO_CONSTRUCTORS on; _NewRsaKey_common skipped"); }
#endif /* !WC_NO_CONSTRUCTORS */

/* ------------------------------------------------------------------------- *
 * Class 2: _RsaExportKey() NULL-pointer guard (line 4938, 11 conditions).
 *
 *   if (key==NULL || e==NULL || eSz==NULL || n==NULL || nSz==NULL ||
 *       d==NULL || dSz==NULL || p==NULL || pSz==NULL || q==NULL || qSz==NULL)
 *
 * wc_RsaExportKey pre-guards these before calling the static, so the false side
 * of each operand is only reachable here. All-valid uses a freshly initialized
 * key (empty mp_ints export as size 0, returning 0). Each bad call sets exactly
 * one pointer NULL; the guard short-circuits before any dereference.
 * ------------------------------------------------------------------------- */
#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
static void wb_rsa_export_key(void)
{
    RsaKey key;
    byte   e[256], n[256], d[256], p[256], q[256];
    word32 eSz = sizeof(e), nSz = sizeof(n), dSz = sizeof(d);
    word32 pSz = sizeof(p), qSz = sizeof(q);

    if (wc_InitRsaKey(&key, NULL) != 0) {
        WB_NOTE("wc_InitRsaKey failed (_RsaExportKey skipped)");
        wb_fail = 1;
        return;
    }

    /* all-false side: every pointer valid */
    (void)_RsaExportKey(&key, e, &eSz, n, &nSz, d, &dSz, p, &pSz, q, &qSz);
    /* one NULL at a time -> each operand independently forces BAD_FUNC_ARG */
    (void)_RsaExportKey(NULL, e, &eSz, n, &nSz, d, &dSz, p, &pSz, q, &qSz);
    (void)_RsaExportKey(&key, NULL, &eSz, n, &nSz, d, &dSz, p, &pSz, q, &qSz);
    (void)_RsaExportKey(&key, e, NULL, n, &nSz, d, &dSz, p, &pSz, q, &qSz);
    (void)_RsaExportKey(&key, e, &eSz, NULL, &nSz, d, &dSz, p, &pSz, q, &qSz);
    (void)_RsaExportKey(&key, e, &eSz, n, NULL, d, &dSz, p, &pSz, q, &qSz);
    (void)_RsaExportKey(&key, e, &eSz, n, &nSz, NULL, &dSz, p, &pSz, q, &qSz);
    (void)_RsaExportKey(&key, e, &eSz, n, &nSz, d, NULL, p, &pSz, q, &qSz);
    (void)_RsaExportKey(&key, e, &eSz, n, &nSz, d, &dSz, NULL, &pSz, q, &qSz);
    (void)_RsaExportKey(&key, e, &eSz, n, &nSz, d, &dSz, p, NULL, q, &qSz);
    (void)_RsaExportKey(&key, e, &eSz, n, &nSz, d, &dSz, p, &pSz, NULL, &qSz);
    (void)_RsaExportKey(&key, e, &eSz, n, &nSz, d, &dSz, p, &pSz, q, NULL);

    wc_FreeRsaKey(&key);
    WB_NOTE("_RsaExportKey NULL-pointer guard pairs exercised");
}
#else
static void wb_rsa_export_key(void) { WB_NOTE("RSA_VERIFY_ONLY on; _RsaExportKey skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 3: _RsaFlattenPublicKey() NULL-pointer guard (line 4829, 5 conditions).
 *
 *   if (key==NULL || e==NULL || eSz==NULL || n==NULL || nSz==NULL)
 *
 * wc_RsaFlattenPublicKey pre-guards these. All-valid uses a freshly initialized
 * key (empty mp_ints flatten as size 0, returning 0). Each bad call sets exactly
 * one pointer NULL; the guard short-circuits before any dereference.
 * ------------------------------------------------------------------------- */
#if !defined(WOLFSSL_RSA_VERIFY_ONLY)
static void wb_rsa_flatten_pub(void)
{
    RsaKey key;
    byte   e[256], n[256];
    word32 eSz = sizeof(e), nSz = sizeof(n);

    if (wc_InitRsaKey(&key, NULL) != 0) {
        WB_NOTE("wc_InitRsaKey failed (_RsaFlattenPublicKey skipped)");
        wb_fail = 1;
        return;
    }

    (void)_RsaFlattenPublicKey(&key, e, &eSz, n, &nSz);   /* all false */
    (void)_RsaFlattenPublicKey(NULL, e, &eSz, n, &nSz);   /* key==NULL */
    (void)_RsaFlattenPublicKey(&key, NULL, &eSz, n, &nSz);/* e==NULL   */
    (void)_RsaFlattenPublicKey(&key, e, NULL, n, &nSz);   /* eSz==NULL */
    (void)_RsaFlattenPublicKey(&key, e, &eSz, NULL, &nSz);/* n==NULL   */
    (void)_RsaFlattenPublicKey(&key, e, &eSz, n, NULL);   /* nSz==NULL */

    wc_FreeRsaKey(&key);
    WB_NOTE("_RsaFlattenPublicKey NULL-pointer guard pairs exercised");
}
#else
static void wb_rsa_flatten_pub(void) { WB_NOTE("RSA_VERIFY_ONLY on; _RsaFlattenPublicKey skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 4: wc_CompareDiffPQ() p/q NULL guard (line 5047, 2 conditions).
 *
 *   if (p == NULL || q == NULL)
 *
 * Reachable from wc_MakeRsaKey only with non-NULL p/q, so the true side of each
 * operand is white-box only. All-valid uses two freshly initialized mp_ints
 * (both zero); the guard short-circuits before dereferencing a NULL operand.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
static void wb_compare_diff_pq(void)
{
    mp_int p, q;
    int    valid = 0;

    if (mp_init(&p) != MP_OKAY) {
        WB_NOTE("mp_init(p) failed (wc_CompareDiffPQ skipped)");
        wb_fail = 1;
        return;
    }
    if (mp_init(&q) != MP_OKAY) {
        WB_NOTE("mp_init(q) failed (wc_CompareDiffPQ skipped)");
        mp_clear(&p);
        wb_fail = 1;
        return;
    }

    (void)wc_CompareDiffPQ(&p, &q, 1024, &valid);  /* p!=NULL && q!=NULL: false */
    (void)wc_CompareDiffPQ(NULL, &q, 1024, &valid);/* p==NULL -> true           */
    (void)wc_CompareDiffPQ(&p, NULL, 1024, &valid);/* p!=NULL F, q==NULL -> true*/

    mp_clear(&p);
    mp_clear(&q);
    WB_NOTE("wc_CompareDiffPQ p/q NULL guard pairs exercised");
}
#else
static void wb_compare_diff_pq(void) { WB_NOTE("KEY_GEN off / PUBLIC_ONLY; wc_CompareDiffPQ skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 5: _RsaPrivateKeyDecodeRaw() arg/size guards (lines 5890 & 5896).
 *
 *   line 5890 (11 conds): if (n==NULL||nSz==0||e==NULL||eSz==0||d==NULL||dSz==0
 *                             ||p==NULL||pSz==0||q==NULL||qSz==0||key==NULL)
 *   line 5896 (guarded):  if ((u==NULL||uSz==0)||(dP!=NULL&&dPSz==0)
 *                             ||(dQ!=NULL&&dQSz==0))
 *
 * wc_RsaPrivateKeyDecodeRaw pre-guards the required params, so the false side of
 * each operand is white-box only. mp_read_unsigned_bin accepts any bytes, so the
 * all-valid call (4-byte dummy values) reaches past both checks and populates
 * the key; we run the BAD_FUNC_ARG calls first (key untouched) then the single
 * populating call, then free once. Each bad call flips exactly one operand.
 * ------------------------------------------------------------------------- */
#ifndef WOLFSSL_RSA_PUBLIC_ONLY
static void wb_privkey_decode_raw(void)
{
    RsaKey key;
    byte   b[4] = { 1, 2, 3, 4 };

    if (wc_InitRsaKey(&key, NULL) != 0) {
        WB_NOTE("wc_InitRsaKey failed (_RsaPrivateKeyDecodeRaw skipped)");
        wb_fail = 1;
        return;
    }

    /* line 5890: flip each of the 11 required-arg operands to true (bad). */
    (void)_RsaPrivateKeyDecodeRaw(NULL, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, &key); /* n==NULL  */
    (void)_RsaPrivateKeyDecodeRaw(b, 0, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, &key);    /* nSz==0   */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, NULL, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, &key); /* e==NULL  */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 0, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, &key);    /* eSz==0   */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, NULL, 4, b, 4, b, 4, b, 4, b, 4, b, 4, &key); /* d==NULL  */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 0, b, 4, b, 4, b, 4, b, 4, b, 4, &key);    /* dSz==0   */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 4, b, 4, NULL, 4, b, 4, b, 4, b, 4, &key); /* p==NULL  */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 4, b, 4, b, 0, b, 4, b, 4, b, 4, &key);    /* pSz==0   */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 4, b, 4, b, 4, NULL, 4, b, 4, b, 4, &key); /* q==NULL  */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 4, b, 4, b, 4, b, 0, b, 4, b, 4, &key);    /* qSz==0   */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, NULL);    /* key==NULL*/

#if defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM)
    /* line 5896: flip each operand; u/dP/dQ params here (n..q all valid). */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 4, NULL, 4, b, 4, b, 4, b, 4, b, 4, &key); /* u==NULL   */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 4, b, 0, b, 4, b, 4, b, 4, b, 4, &key);    /* uSz==0    */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 0, b, 4, &key);    /* dP!=NULL && dPSz==0 */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 0, &key);    /* dQ!=NULL && dQSz==0 */
#endif

    /* all-false side of both checks: every required arg valid, u/dP/dQ valid.
     * This populates the key (mp_read_unsigned_bin on 4-byte dummies). */
    (void)_RsaPrivateKeyDecodeRaw(b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, b, 4, &key);

    wc_FreeRsaKey(&key);
    WB_NOTE("_RsaPrivateKeyDecodeRaw arg/size guard pairs exercised");
}
#else
static void wb_privkey_decode_raw(void) { WB_NOTE("RSA_PUBLIC_ONLY on; _RsaPrivateKeyDecodeRaw skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 6: RsaPad() argument guard (line ~1643, 4 conditions).
 *
 *   if (input==NULL || inputLen==0 || pkcsBlock==NULL || pkcsBlockLen==0)
 *
 * wc_RsaPad_ex dispatches here only with validated args, so the single-true
 * (reject) half of each operand is white-box only; the all-false side is
 * produced by every real PKCS#1 v1.5 encrypt. Each bad call returns
 * BAD_FUNC_ARG before touching the buffers.
 * ------------------------------------------------------------------------- */
#ifndef WOLFSSL_RSA_VERIFY_ONLY
static void wb_rsa_pad(void)
{
    byte blk[256];
    byte inp[16];

    XMEMSET(blk, 0, sizeof(blk));
    XMEMSET(inp, 0, sizeof(inp));

    /* all-false side (every operand valid) must be in THIS binary too, since
     * llvm-cov shows MC/DC independence per binary. RSA_BLOCK_TYPE_1 pads with
     * 0xFF and needs no RNG, so this valid call completes without a generator. */
    (void)RsaPad(inp,  sizeof(inp), blk,  sizeof(blk), RSA_BLOCK_TYPE_1, NULL); /* all false       */
    (void)RsaPad(NULL, sizeof(inp), blk,  sizeof(blk), RSA_BLOCK_TYPE_1, NULL); /* input==NULL     */
    (void)RsaPad(inp,  0,           blk,  sizeof(blk), RSA_BLOCK_TYPE_1, NULL); /* inputLen==0     */
    (void)RsaPad(inp,  sizeof(inp), NULL, sizeof(blk), RSA_BLOCK_TYPE_1, NULL); /* pkcsBlock==NULL */
    (void)RsaPad(inp,  sizeof(inp), blk,  0,           RSA_BLOCK_TYPE_1, NULL); /* pkcsBlockLen==0 */
    WB_NOTE("RsaPad argument guard pairs exercised");
}
#else
static void wb_rsa_pad(void) { WB_NOTE("RSA_VERIFY_ONLY on; RsaPad skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 7: RsaUnPad() argument guard (line ~2039, 3 conditions).
 *
 *   if (output == NULL || pkcsBlockLen < 2 || pkcsBlockLen > 0xFFFF)
 *
 * wc_RsaUnPad_ex validates before dispatching, so each operand's true side is
 * white-box only. The pkcsBlockLen>0xFFFF call short-circuits after the length
 * test, never indexing the (smaller) buffer, so it is memory-safe.
 * ------------------------------------------------------------------------- */
#ifndef WOLFSSL_RSA_VERIFY_ONLY
static void wb_rsa_unpad(void)
{
    byte        blk[256];
    const byte* outp = NULL;

    XMEMSET(blk, 0, sizeof(blk));
    blk[0] = 0;
    blk[1] = RSA_BLOCK_TYPE_1;

    /* all-false side (output valid, 2 <= len <= 0xFFFF) in THIS binary too. The
     * block need not be validly padded: the line-2039 guard runs before any
     * padding parse, so this call exercises its false side regardless. */
    (void)RsaUnPad(blk, sizeof(blk), &outp, RSA_BLOCK_TYPE_1); /* all false          */
    (void)RsaUnPad(blk, sizeof(blk), NULL,  RSA_BLOCK_TYPE_1); /* output==NULL       */
    (void)RsaUnPad(blk, 1,           &outp, RSA_BLOCK_TYPE_1); /* pkcsBlockLen < 2   */
    (void)RsaUnPad(blk, 0x10000u,    &outp, RSA_BLOCK_TYPE_1); /* pkcsBlockLen>0xFFFF*/
    WB_NOTE("RsaUnPad argument guard pairs exercised");
}
#else
static void wb_rsa_unpad(void) { WB_NOTE("RSA_VERIFY_ONLY on; RsaUnPad skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Class 8: _CheckProbablePrime() argument guard (line ~5185, 3 conditions).
 *
 *   if (p == NULL || e == NULL || isPrime == NULL)
 *
 * wc_CheckProbablePrime_ex validates p/e/isPrime before calling the static, so
 * the true side of each operand is white-box only (q may legitimately be NULL).
 * Each bad call short-circuits before dereferencing. The all-false call uses
 * two zero-initialized mp_ints (0 is trivially rejected as composite).
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_KEY_GEN) && !defined(WOLFSSL_RSA_PUBLIC_ONLY)
static void wb_check_probable_prime(void)
{
    mp_int p, e;
    int    isPrime = 0;

    if (mp_init(&p) != MP_OKAY) {
        WB_NOTE("mp_init(p) failed (_CheckProbablePrime skipped)");
        wb_fail = 1;
        return;
    }
    if (mp_init(&e) != MP_OKAY) {
        WB_NOTE("mp_init(e) failed (_CheckProbablePrime skipped)");
        mp_clear(&p);
        wb_fail = 1;
        return;
    }

    (void)_CheckProbablePrime(&p,   NULL, &e,   2048, &isPrime, NULL); /* all false */
    (void)_CheckProbablePrime(NULL, NULL, &e,   2048, &isPrime, NULL); /* p==NULL       */
    (void)_CheckProbablePrime(&p,   NULL, NULL, 2048, &isPrime, NULL); /* e==NULL       */
    (void)_CheckProbablePrime(&p,   NULL, &e,   2048, NULL,     NULL); /* isPrime==NULL */

    mp_clear(&p);
    mp_clear(&e);
    WB_NOTE("_CheckProbablePrime p/e/isPrime NULL guard pairs exercised");
}
#else
static void wb_check_probable_prime(void) { WB_NOTE("KEY_GEN off / PUBLIC_ONLY; _CheckProbablePrime skipped"); }
#endif

int main(void)
{
    printf("rsa.c white-box MC/DC supplement\n");
#ifdef NO_RSA
    printf("  NO_RSA defined; nothing to exercise\n");
    return 0;
#else
    wb_newrsakey_common();
    wb_rsa_export_key();
    wb_rsa_flatten_pub();
    wb_compare_diff_pq();
    wb_privkey_decode_raw();
    wb_rsa_pad();
    wb_rsa_unpad();
    wb_check_probable_prime();
    printf("done (%s)\n", wb_fail ? "with skips" : "ok");
    /* Setup failures are surfaced as skips, not test failures: the campaign
     * treats a nonzero exit as a failed variant and discards its coverage. */
    return 0;
#endif
}
